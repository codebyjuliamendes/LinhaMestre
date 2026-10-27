"""Acesso a dados (SQLite): conexão, esquema/migrações e repositório."""

from __future__ import annotations

import logging
import sqlite3
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from . import security
from .domain import TASK_DONE, TASK_PENDING, AccessLevel, ProductInput
from .security import PasswordHash, generate_password, hash_password, needs_rehash, verify_password

log = logging.getLogger("linhamestre.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     username TEXT UNIQUE,
     password TEXT,
     name TEXT,
     email TEXT,
     access_level TEXT,
     salt TEXT,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS products
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     name TEXT,
     category TEXT,
     quantity INTEGER,
     min_quantity INTEGER,
     unit TEXT,
     location TEXT,
     supplier TEXT,
     cost REAL,
     price REAL,
     barcode TEXT,
     production_date DATE,
     expiry_date DATE,
     quality_status TEXT,
     notes TEXT,
     created_by INTEGER,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     updated_at TIMESTAMP,
     FOREIGN KEY(created_by) REFERENCES users(id));

CREATE TABLE IF NOT EXISTS messages
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     sender_id INTEGER,
     receiver_id INTEGER,
     subject TEXT,
     content TEXT,
     is_read INTEGER DEFAULT 0,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     FOREIGN KEY(sender_id) REFERENCES users(id),
     FOREIGN KEY(receiver_id) REFERENCES users(id));

CREATE TABLE IF NOT EXISTS tasks
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     title TEXT,
     description TEXT,
     assigned_to INTEGER,
     created_by INTEGER,
     priority TEXT,
     status TEXT DEFAULT 'Pendente',
     due_date DATE,
     completed_at TIMESTAMP,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     FOREIGN KEY(assigned_to) REFERENCES users(id),
     FOREIGN KEY(created_by) REFERENCES users(id));

CREATE TABLE IF NOT EXISTS quality_control
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     product_id INTEGER,
     control_date DATE,
     sample_size INTEGER,
     mean_value REAL,
     range_value REAL,
     std_dev REAL,
     created_by INTEGER,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     FOREIGN KEY(product_id) REFERENCES products(id),
     FOREIGN KEY(created_by) REFERENCES users(id));

CREATE TABLE IF NOT EXISTS audit_logs
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
     user_id INTEGER,
     action TEXT,
     details TEXT,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     FOREIGN KEY(user_id) REFERENCES users(id));

CREATE TABLE IF NOT EXISTS app_settings
    (key TEXT PRIMARY KEY,
     value TEXT NOT NULL);

CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id, is_read);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_qc_product_date ON quality_control(product_id, control_date);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
"""

DEFAULT_APP_SETTINGS: dict[str, int] = {"expiry_warning_days": 30, "default_min_quantity": 5}


def connect(path: Path | str) -> sqlite3.Connection:
    """Abre uma conexão nova. Use uma conexão por execução do script (thread)."""
    path = Path(path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def open_db(path: Path | str) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
    finally:
        conn.close()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def bootstrap_admin(conn: sqlite3.Connection, username: str, password: str | None) -> str | None:
    """Cria o administrador inicial se não houver usuários.

    Retorna a senha gerada quando nenhuma foi informada (para ser exibida uma vez no log).
    """
    (count,) = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    if count:
        return None
    generated = None
    if not password:
        password = generated = generate_password()
    ph = hash_password(password)
    with conn:
        conn.execute(
            "INSERT INTO users (username, password, name, email, access_level, salt) VALUES (?, ?, ?, ?, ?, ?)",
            (username, ph.hashed, "Administrador", "", AccessLevel.ADMINISTRADOR.value, ph.salt),
        )
        conn.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (NULL, 'SYSTEM_INIT', ?)",
            (f"Administrador inicial '{username}' criado.",),
        )
    log.info("admin_bootstrap", extra={"username": username, "generated_password": generated is not None})
    return generated


def _iso(d: date | None) -> str | None:
    return d.isoformat() if d else None


@dataclass(frozen=True, slots=True)
class User:
    id: int
    username: str
    name: str
    email: str
    access_level: str


def _user(row: sqlite3.Row) -> User:
    return User(row["id"], row["username"], row["name"] or "", row["email"] or "", row["access_level"] or "")


class Repository:
    """Operações de dados. Cada escrita relevante grava auditoria na mesma transação."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ----------------------------------------------------------------- utilitários
    def _all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, tuple(params)).fetchall())

    def _one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute(sql, tuple(params)).fetchone()
        return row

    def _scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self.conn.execute(sql, tuple(params)).fetchone()
        return row[0] if row else None

    def _audit(self, user_id: int | None, action: str, details: str) -> None:
        self.conn.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)", (user_id, action, details)
        )

    def log_audit(self, user_id: int | None, action: str, details: str) -> None:
        with self.conn:
            self._audit(user_id, action, details)

    def list_audit(self, limit: int = 200) -> list[sqlite3.Row]:
        return self._all(
            """SELECT a.created_at, COALESCE(u.username, '(sistema)') AS username, a.action, a.details
               FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
               ORDER BY a.id DESC LIMIT ?""",
            (limit,),
        )

    # ----------------------------------------------------------------- usuários
    def authenticate(self, username: str, password: str) -> User | None:
        row = self._one(
            "SELECT id, username, name, email, access_level, password, salt FROM users WHERE username = ?",
            (username.strip(),),
        )
        if row is None:
            # Executa um hash mesmo sem usuário para não revelar existência pelo tempo de resposta.
            verify_password(password, f"pbkdf2_sha256${security.PBKDF2_ITERATIONS}$00", "00")
            return None
        if not verify_password(password, row["password"], row["salt"]):
            return None
        if needs_rehash(row["password"]):
            ph = hash_password(password)
            with self.conn:
                self.conn.execute(
                    "UPDATE users SET password = ?, salt = ? WHERE id = ?", (ph.hashed, ph.salt, row["id"])
                )
        return _user(row)

    def get_user(self, user_id: int) -> User | None:
        row = self._one("SELECT id, username, name, email, access_level FROM users WHERE id = ?", (user_id,))
        return _user(row) if row else None

    def list_users(self) -> list[sqlite3.Row]:
        return self._all(
            "SELECT id, username, name, email, access_level, created_at FROM users ORDER BY name, username"
        )

    def other_users(self, user_id: int) -> list[User]:
        rows = self._all(
            "SELECT id, username, name, email, access_level FROM users WHERE id != ? ORDER BY name", (user_id,)
        )
        return [_user(r) for r in rows]

    def count_admins(self) -> int:
        return int(
            self._scalar("SELECT COUNT(*) FROM users WHERE access_level = ?", (AccessLevel.ADMINISTRADOR.value,))
        )

    def create_user(
        self, actor_id: int | None, username: str, password_hash: PasswordHash, name: str, email: str, level: str
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO users (username, password, name, email, access_level, salt) VALUES (?, ?, ?, ?, ?, ?)",
                (username, password_hash.hashed, name, email, level, password_hash.salt),
            )
            self._audit(actor_id, "USER_CREATE", f"Usuário '{username}' cadastrado com nível '{level}'.")
        return int(cur.lastrowid or 0)

    def update_user(
        self,
        actor_id: int,
        user_id: int,
        username: str,
        name: str,
        email: str,
        level: str,
        password_hash: PasswordHash | None = None,
    ) -> None:
        with self.conn:
            if password_hash:
                self.conn.execute(
                    "UPDATE users SET username=?, password=?, salt=?, name=?, email=?, access_level=? WHERE id=?",
                    (username, password_hash.hashed, password_hash.salt, name, email, level, user_id),
                )
            else:
                self.conn.execute(
                    "UPDATE users SET username=?, name=?, email=?, access_level=? WHERE id=?",
                    (username, name, email, level, user_id),
                )
            detail = " (senha redefinida)" if password_hash else ""
            self._audit(actor_id, "USER_UPDATE", f"Usuário '{username}' (ID {user_id}) atualizado{detail}.")

    def delete_user(self, actor_id: int, user_id: int) -> None:
        with self.conn:
            row = self._one("SELECT username FROM users WHERE id = ?", (user_id,))
            self.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            name = row["username"] if row else "?"
            self._audit(actor_id, "USER_DELETE", f"Usuário '{name}' (ID {user_id}) excluído.")

    # ----------------------------------------------------------------- configurações
    def get_app_settings(self) -> dict[str, int]:
        values = dict(DEFAULT_APP_SETTINGS)
        for row in self._all("SELECT key, value FROM app_settings"):
            if row["key"] in values:
                try:
                    values[row["key"]] = int(row["value"])
                except ValueError:
                    log.warning("invalid_setting", extra={"key": row["key"]})
        return values

    def save_app_settings(self, actor_id: int, values: dict[str, int]) -> None:
        with self.conn:
            for key, value in values.items():
                if key not in DEFAULT_APP_SETTINGS:
                    raise KeyError(key)
                self.conn.execute(
                    "INSERT INTO app_settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, str(int(value))),
                )
            self._audit(actor_id, "SETTINGS_UPDATE", ", ".join(f"{k}={v}" for k, v in sorted(values.items())))

    # ----------------------------------------------------------------- produtos
    def categories(self) -> list[str]:
        return [r[0] for r in self._all("SELECT DISTINCT category FROM products WHERE category IS NOT NULL ORDER BY 1")]

    def product_options(self) -> list[sqlite3.Row]:
        return self._all("SELECT id, name FROM products ORDER BY name, id")

    def get_product(self, product_id: int) -> sqlite3.Row | None:
        return self._one("SELECT * FROM products WHERE id = ?", (product_id,))

    def list_products(
        self,
        today: date,
        warning_days: int,
        category: str | None = None,
        stock: str | None = None,
        expiry: str | None = None,
    ) -> list[sqlite3.Row]:
        conditions: list[str] = []
        params: list[Any] = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if stock == "Crítico":
            conditions.append("quantity <= min_quantity")
        elif stock == "Normal":
            conditions.append("quantity > min_quantity")
        today_s = today.isoformat()
        until_s = date.fromordinal(today.toordinal() + warning_days).isoformat()
        if expiry == "Válidos":
            conditions.append("(expiry_date IS NULL OR expiry_date >= ?)")
            params.append(today_s)
        elif expiry == "Próximos da Validade":
            conditions.append("expiry_date BETWEEN ? AND ?")
            params.extend([today_s, until_s])
        elif expiry == "Vencidos":
            conditions.append("expiry_date < ?")
            params.append(today_s)
        sql = (
            "SELECT id, name, category, quantity, min_quantity, unit, expiry_date, quality_status, location "
            "FROM products"
        )
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY name, id"
        return self._all(sql, params)

    def _product_params(self, p: ProductInput) -> tuple[Any, ...]:
        return (
            p.name, p.category, p.quantity, p.min_quantity, p.unit, p.location, p.supplier, p.cost, p.price,
            p.barcode, _iso(p.production_date), _iso(p.expiry_date), p.quality_status, p.notes,
        )  # fmt: skip

    def create_product(self, actor_id: int, product: ProductInput) -> int:
        p = product.validated()
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO products
                   (name, category, quantity, min_quantity, unit, location, supplier, cost, price, barcode,
                    production_date, expiry_date, quality_status, notes, created_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (*self._product_params(p), actor_id),
            )
            self._audit(
                actor_id,
                "PRODUCT_CREATE",
                f"Produto '{p.name}' (categoria {p.category}) cadastrado com {p.quantity} {p.unit}.",
            )
        return int(cur.lastrowid or 0)

    def update_product(self, actor_id: int, product_id: int, product: ProductInput) -> None:
        p = product.validated()
        with self.conn:
            cur = self.conn.execute(
                """UPDATE products SET name=?, category=?, quantity=?, min_quantity=?, unit=?, location=?,
                   supplier=?, cost=?, price=?, barcode=?, production_date=?, expiry_date=?, quality_status=?,
                   notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (*self._product_params(p), product_id),
            )
            if cur.rowcount == 0:
                raise LookupError("Produto não encontrado.")
            self._audit(actor_id, "PRODUCT_UPDATE", f"Produto '{p.name}' (ID {product_id}) atualizado.")

    def delete_product(self, actor_id: int, product_id: int) -> None:
        with self.conn:
            row = self._one("SELECT name FROM products WHERE id = ?", (product_id,))
            if row is None:
                raise LookupError("Produto não encontrado.")
            self.conn.execute("DELETE FROM quality_control WHERE product_id = ?", (product_id,))
            self.conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
            self._audit(
                actor_id, "PRODUCT_DELETE", f"Produto '{row['name']}' (ID {product_id}) e suas medições excluídos."
            )

    def dashboard_counts(self, user_id: int, today: date, warning_days: int) -> dict[str, int]:
        until = date.fromordinal(today.toordinal() + warning_days).isoformat()
        return {
            "products": int(self._scalar("SELECT COUNT(*) FROM products")),
            "critical": int(self._scalar("SELECT COUNT(*) FROM products WHERE quantity <= min_quantity")),
            "expiring": int(
                self._scalar(
                    "SELECT COUNT(*) FROM products WHERE expiry_date BETWEEN ? AND ?", (today.isoformat(), until)
                )
            ),
            "pending_tasks": int(
                self._scalar("SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status = ?", (user_id, TASK_PENDING))
            ),
        }

    def stock_by_category(self) -> list[sqlite3.Row]:
        return self._all(
            """SELECT COALESCE(category, '(sem categoria)') AS category, SUM(quantity) AS total_quantity,
                      COUNT(*) AS product_count, AVG(price) AS avg_price
               FROM products GROUP BY category ORDER BY total_quantity DESC"""
        )

    def expiring_products(self, today: date, warning_days: int, limit: int = 10) -> list[sqlite3.Row]:
        until = date.fromordinal(today.toordinal() + warning_days).isoformat()
        return self._all(
            """SELECT name, expiry_date, quantity FROM products WHERE expiry_date BETWEEN ? AND ?
               ORDER BY expiry_date ASC LIMIT ?""",
            (today.isoformat(), until, limit),
        )

    def critical_products(self, limit: int | None = None) -> list[sqlite3.Row]:
        sql = """SELECT name, category, quantity, min_quantity, unit, location,
                        CASE WHEN min_quantity > 0 THEN quantity * 100.0 / min_quantity END AS pct
                 FROM products WHERE quantity <= min_quantity
                 ORDER BY pct IS NULL, pct ASC, name"""
        if limit is not None:
            return self._all(sql + " LIMIT ?", (limit,))
        return self._all(sql)

    def expiry_report(self, today: date, warning_days: int) -> list[sqlite3.Row]:
        until = date.fromordinal(today.toordinal() + warning_days).isoformat()
        return self._all(
            """SELECT CASE
                        WHEN expiry_date IS NULL OR expiry_date = '' THEN 'Sem Validade'
                        WHEN expiry_date < ? THEN 'Vencidos'
                        WHEN expiry_date <= ? THEN 'Próximos da Validade'
                        ELSE 'Válidos' END AS status,
                      COUNT(*) AS count, SUM(quantity) AS total_quantity
               FROM products GROUP BY status
               ORDER BY CASE status WHEN 'Vencidos' THEN 1 WHEN 'Próximos da Validade' THEN 2
                                    WHEN 'Válidos' THEN 3 ELSE 4 END""",
            (today.isoformat(), until),
        )

    def quality_status_counts(self) -> list[sqlite3.Row]:
        return self._all(
            """SELECT COALESCE(quality_status, '(sem status)') AS quality_status, COUNT(*) AS count,
                      SUM(quantity) AS total_quantity
               FROM products GROUP BY quality_status ORDER BY count DESC"""
        )

    # ----------------------------------------------------------------- controle de qualidade
    def products_with_qc(self) -> set[int]:
        return {int(r[0]) for r in self._all("SELECT DISTINCT product_id FROM quality_control")}

    def qc_rows(self, product_id: int) -> list[sqlite3.Row]:
        return self._all(
            """SELECT control_date, sample_size, mean_value, range_value, std_dev FROM quality_control
               WHERE product_id = ? AND mean_value IS NOT NULL ORDER BY control_date, id""",
            (product_id,),
        )

    def add_qc(
        self,
        actor_id: int,
        product_id: int,
        control_date: date,
        sample_size: int,
        mean_value: float,
        range_value: float,
        std_dev: float,
    ) -> None:
        if range_value < 0 or std_dev < 0:
            raise ValueError("Amplitude e desvio padrão não podem ser negativos.")
        with self.conn:
            if self._one("SELECT 1 FROM products WHERE id = ?", (product_id,)) is None:
                raise LookupError("Produto não encontrado.")
            self.conn.execute(
                """INSERT INTO quality_control
                   (product_id, control_date, sample_size, mean_value, range_value, std_dev, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (product_id, control_date.isoformat(), sample_size, mean_value, range_value, std_dev, actor_id),
            )
            self._audit(
                actor_id,
                "QC_CREATE",
                f"Medição de {control_date.isoformat()} registrada para o produto ID {product_id}.",
            )

    # ----------------------------------------------------------------- mensagens
    def inbox(self, user_id: int, read: bool | None = None, sender_id: int | None = None) -> list[sqlite3.Row]:
        sql = """SELECT m.id, m.sender_id, COALESCE(u.name, '(usuário removido)') AS sender, m.subject, m.content,
                        m.is_read, m.created_at
                 FROM messages m LEFT JOIN users u ON m.sender_id = u.id WHERE m.receiver_id = ?"""
        params: list[Any] = [user_id]
        if read is not None:
            sql += " AND m.is_read = ?"
            params.append(1 if read else 0)
        if sender_id is not None:
            sql += " AND m.sender_id = ?"
            params.append(sender_id)
        return self._all(sql + " ORDER BY m.created_at DESC, m.id DESC", params)

    def sent(self, user_id: int) -> list[sqlite3.Row]:
        return self._all(
            """SELECT m.id, COALESCE(u.name, '(usuário removido)') AS recipient, m.subject, m.content, m.is_read,
                      m.created_at
               FROM messages m LEFT JOIN users u ON m.receiver_id = u.id
               WHERE m.sender_id = ? ORDER BY m.created_at DESC, m.id DESC""",
            (user_id,),
        )

    def send_message(self, sender_id: int, receiver_id: int, subject: str, content: str) -> None:
        subject, content = subject.strip(), content.strip()
        if not subject or not content:
            raise ValueError("Assunto e mensagem são obrigatórios.")
        if sender_id == receiver_id:
            raise ValueError("Não é possível enviar mensagem para si mesmo.")
        with self.conn:
            if self._one("SELECT 1 FROM users WHERE id = ?", (receiver_id,)) is None:
                raise LookupError("Destinatário não encontrado.")
            self.conn.execute(
                "INSERT INTO messages (sender_id, receiver_id, subject, content) VALUES (?, ?, ?, ?)",
                (sender_id, receiver_id, subject, content),
            )
            self._audit(sender_id, "MESSAGE_SEND", f"Mensagem enviada ao usuário ID {receiver_id}.")

    def mark_read(self, message_id: int, user_id: int) -> bool:
        """Marca como lida apenas se a mensagem pertence ao usuário."""
        with self.conn:
            cur = self.conn.execute(
                "UPDATE messages SET is_read = 1 WHERE id = ? AND receiver_id = ?", (message_id, user_id)
            )
        return cur.rowcount > 0

    # ----------------------------------------------------------------- tarefas
    def tasks(
        self,
        today: date,
        assigned_to: int | None = None,
        status: str | None = None,
        priority: str | None = None,
    ) -> list[sqlite3.Row]:
        sql = """SELECT t.id, t.title, t.description, t.priority, t.status, t.due_date, t.completed_at,
                        t.created_at, t.assigned_to,
                        COALESCE(a.name, '(usuário removido)') AS assignee,
                        COALESCE(c.name, '(usuário removido)') AS creator
                 FROM tasks t
                 LEFT JOIN users a ON t.assigned_to = a.id
                 LEFT JOIN users c ON t.created_by = c.id"""
        conditions: list[str] = []
        params: list[Any] = []
        if assigned_to is not None:
            conditions.append("t.assigned_to = ?")
            params.append(assigned_to)
        if status == "Atrasada":
            conditions.append("t.status = ? AND t.due_date < ?")
            params.extend([TASK_PENDING, today.isoformat()])
        elif status:
            conditions.append("t.status = ?")
            params.append(status)
        if priority:
            conditions.append("t.priority = ?")
            params.append(priority)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY t.due_date IS NULL, t.due_date, t.id"
        return self._all(sql, params)

    def create_task(
        self, actor_id: int, title: str, description: str, assignee_id: int, priority: str, due: date | None
    ) -> int:
        title, description = title.strip(), description.strip()
        if not title or not description:
            raise ValueError("Título e descrição são obrigatórios.")
        with self.conn:
            if self._one("SELECT 1 FROM users WHERE id = ?", (assignee_id,)) is None:
                raise LookupError("Responsável não encontrado.")
            cur = self.conn.execute(
                """INSERT INTO tasks (title, description, assigned_to, created_by, priority, due_date, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (title, description, assignee_id, actor_id, priority, _iso(due), TASK_PENDING),
            )
            self._audit(actor_id, "TASK_CREATE", f"Tarefa '{title}' atribuída ao usuário ID {assignee_id}.")
        return int(cur.lastrowid or 0)

    def complete_task(self, actor_id: int, task_id: int, *, any_task: bool = False) -> bool:
        """Conclui a tarefa. Sem ``any_task`` só conclui tarefas atribuídas ao próprio usuário."""
        sql = "UPDATE tasks SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?"
        params: list[Any] = [TASK_DONE, task_id, TASK_PENDING]
        if not any_task:
            sql += " AND assigned_to = ?"
            params.append(actor_id)
        with self.conn:
            cur = self.conn.execute(sql, params)
            if cur.rowcount:
                self._audit(actor_id, "TASK_COMPLETE", f"Tarefa ID {task_id} concluída.")
        return cur.rowcount > 0

    # ----------------------------------------------------------------- backup
    def backup_bytes(self) -> bytes:
        """Cópia consistente do banco (API de backup do SQLite)."""
        with tempfile.TemporaryDirectory() as tmp:
            target_path = Path(tmp) / "backup.db"
            target = sqlite3.connect(str(target_path))
            try:
                self.conn.backup(target)
            finally:
                target.close()
            return target_path.read_bytes()
