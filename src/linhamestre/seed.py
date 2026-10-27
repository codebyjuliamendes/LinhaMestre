"""Popula o banco com dados de DEMONSTRAÇÃO (produtos, medições, tarefas, mensagens).

Uso: ``uv run linhamestre-seed`` (ou ``python seed_db.py``). Idempotente.
Os dados gerados são fictícios e servem apenas para explorar a aplicação.
"""

from __future__ import annotations

import argparse
import os
import random
import sqlite3
import sys
from datetime import date, datetime, timedelta

from .config import load_settings
from .db import bootstrap_admin, init_schema, open_db
from .domain import AccessLevel
from .security import generate_password, hash_password, password_problems

DEMO_USERS = [
    ("ceo", "CEO", AccessLevel.CEO),
    ("gerente", "Gerente Geral", AccessLevel.GERENTE),
    ("supervisor", "Supervisor", AccessLevel.SUPERVISOR),
    ("operacional", "Operacional", AccessLevel.OPERACIONAL),
]

DEMO_PRODUCTS = [
    # name, category, quantity, min_quantity, unit, location, supplier, cost, price, barcode, quality_status
    ("Chapa de Aço Galv 2mm", "Matéria-Prima", 120, 50, "Unidade", "Setor A - P1", "Fornecedor A", 45.0, 95.0, "789123456001", "Aprovado"),
    ("Parafuso Sextavado M12", "Fixadores", 5000, 1000, "Unidade", "Setor B - G3", "Fornecedor B", 0.15, 0.45, "789123456002", "Aprovado"),
    ("Tinta Epóxi Azul 3.6L", "Químicos", 12, 15, "Litro", "Setor C - Inflamáveis", "Fornecedor C", 120.0, 250.0, "789123456003", "Aprovado"),
    ("Eixo de Transmissão 50mm", "Componentes", 8, 10, "Unidade", "Setor A - P4", "Fornecedor D", 340.0, 680.0, "789123456004", "Em Análise"),
    ("Filtro de Óleo Hidráulico", "Manutenção", 4, 5, "Unidade", "Setor D - Estante 2", "Fornecedor E", 85.0, 160.0, "789123456005", "Reprovado"),
    ("Cabo de Cobre Flexível 6mm", "Elétrica", 400, 200, "Metro", "Setor E - Bobinas", "Fornecedor F", 4.20, 8.90, "789123456006", "Aprovado"),
]  # fmt: skip

# Valor nominal e desvio padrão simulados para os produtos com medições.
_QC_PROFILES = {"Chapa de Aço Galv 2mm": (2.0, 0.05), "Parafuso Sextavado M12": (12.0, 0.12)}


def _user_id(conn: sqlite3.Connection, username: str) -> int | None:
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    return int(row[0]) if row else None


def seed(conn: sqlite3.Connection, *, today: date, demo_password: str | None, rng: random.Random) -> dict[str, int]:
    """Insere dados de demonstração que ainda não existam. Retorna contagens inseridas."""
    inserted = {"users": 0, "products": 0, "qc": 0, "tasks": 0, "messages": 0}
    admin_id = int(
        conn.execute("SELECT MIN(id) FROM users WHERE access_level = ?", (AccessLevel.ADMINISTRADOR.value,)).fetchone()[
            0
        ]
    )

    with conn:
        if demo_password:
            for username, name, level in DEMO_USERS:
                if _user_id(conn, username) is None:
                    ph = hash_password(demo_password)
                    conn.execute(
                        "INSERT INTO users (username, password, name, email, access_level, salt) VALUES (?, ?, ?, ?, ?, ?)",
                        (username, ph.hashed, name, "", level.value, ph.salt),
                    )
                    inserted["users"] += 1
        supervisor_id = _user_id(conn, "supervisor") or admin_id

        product_ids: dict[str, int] = {}
        for name, cat, qty, min_qty, unit, loc, sup, cost, price, bar, status in DEMO_PRODUCTS:
            row = conn.execute("SELECT id FROM products WHERE name = ?", (name,)).fetchone()
            if row:
                product_ids[name] = int(row[0])
                continue
            production = today - timedelta(days=rng.randint(5, 45))
            expiry = today + timedelta(days=rng.randint(20, 365))
            cur = conn.execute(
                """INSERT INTO products (name, category, quantity, min_quantity, unit, location, supplier, cost, price,
                   barcode, production_date, expiry_date, quality_status, notes, created_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (name, cat, qty, min_qty, unit, loc, sup, cost, price, bar, production.isoformat(), expiry.isoformat(),
                 status, "Lote de demonstração", admin_id),
            )  # fmt: skip
            product_ids[name] = int(cur.lastrowid or 0)
            inserted["products"] += 1

        for name, (nominal, sd) in _QC_PROFILES.items():
            product_id = product_ids[name]
            start = today - timedelta(days=25)
            for i in range(25):
                control_date = (start + timedelta(days=i)).isoformat()
                exists = conn.execute(
                    "SELECT 1 FROM quality_control WHERE product_id = ? AND control_date = ?",
                    (product_id, control_date),
                ).fetchone()
                if exists:
                    continue
                # Leve deslocamento nos últimos dias para ilustrar os alertas de Western Electric.
                drift = sd * 1.5 if i > 16 else 0.0
                values = [rng.normalvariate(nominal + drift, sd) for _ in range(5)]
                mean = sum(values) / len(values)
                rng_value = max(values) - min(values)
                std = (sum((x - mean) ** 2 for x in values) / (len(values) - 1)) ** 0.5
                conn.execute(
                    """INSERT INTO quality_control (product_id, control_date, sample_size, mean_value, range_value,
                       std_dev, created_by) VALUES (?, ?, 5, ?, ?, ?, ?)""",
                    (product_id, control_date, round(mean, 4), round(rng_value, 4), round(std, 4), supervisor_id),
                )
                inserted["qc"] += 1

        if conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0:
            conn.execute(
                """INSERT INTO tasks (title, description, assigned_to, created_by, priority, status, due_date)
                   VALUES (?, ?, ?, ?, 'Alta', 'Pendente', ?)""",
                ("Auditoria ISO 9001", "Preparar a documentação de controle de qualidade dos últimos 6 meses.",
                 supervisor_id, admin_id, (today + timedelta(days=15)).isoformat()),
            )  # fmt: skip
            conn.execute(
                """INSERT INTO tasks (title, description, assigned_to, created_by, priority, status, due_date)
                   VALUES (?, ?, ?, ?, 'Média', 'Pendente', ?)""",
                ("Verificar lote reprovado", "O filtro de óleo hidráulico foi reprovado. Contatar o fornecedor.",
                 supervisor_id, admin_id, (today + timedelta(days=2)).isoformat()),
            )  # fmt: skip
            inserted["tasks"] += 2

        if conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0 and supervisor_id != admin_id:
            conn.execute(
                "INSERT INTO messages (sender_id, receiver_id, subject, content) VALUES (?, ?, ?, ?)",
                (admin_id, supervisor_id, "Desvio estatístico detectado",
                 "Notamos uma tendência de elevação nos diâmetros dos parafusos nos últimos lotes. "
                 "Por favor, verifique a calibração da máquina."),
            )  # fmt: skip
            inserted["messages"] += 1

        conn.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'SEED', ?)",
            (admin_id, "Dados de demonstração inseridos: " + ", ".join(f"{k}={v}" for k, v in inserted.items())),
        )
    return inserted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--with-demo-users",
        action="store_true",
        help="cria também ceo/gerente/supervisor/operacional com a senha de LINHAMESTRE_DEMO_PASSWORD "
        "(ou uma senha aleatória exibida no terminal)",
    )
    parser.add_argument("--random-seed", type=int, default=None, help="semente para dados reprodutíveis")
    args = parser.parse_args(argv)

    settings = load_settings()
    demo_password: str | None = None
    if args.with_demo_users:
        demo_password = os.environ.get("LINHAMESTRE_DEMO_PASSWORD") or generate_password()
        problems = password_problems(demo_password)
        if problems:
            print("LINHAMESTRE_DEMO_PASSWORD inválida: " + " ".join(problems), file=sys.stderr)
            return 2

    with open_db(settings.db_path) as conn:
        init_schema(conn)
        generated_admin = bootstrap_admin(conn, settings.admin_username, settings.admin_password)
        today = datetime.now(settings.timezone).date()
        counts = seed(conn, today=today, demo_password=demo_password, rng=random.Random(args.random_seed))

    print(f"Banco: {settings.db_path}")
    print("Inseridos: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    if generated_admin:
        print(f"Administrador '{settings.admin_username}' criado com senha gerada: {generated_admin}")
    if demo_password and counts["users"] and not os.environ.get("LINHAMESTRE_DEMO_PASSWORD"):
        print(f"Senha dos usuários de demonstração: {demo_password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
