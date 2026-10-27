import hashlib
import random
import sqlite3
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path

import pytest

from linhamestre import seed
from linhamestre.db import Repository, bootstrap_admin, init_schema, open_db
from linhamestre.domain import ProductInput, ValidationError
from linhamestre.security import hash_password

from .conftest import ADMIN_PASSWORD

TODAY = date(2026, 3, 15)


def _admin(repo: Repository) -> int:
    user = repo.authenticate("admin", ADMIN_PASSWORD)
    assert user is not None
    return user.id


def _product(name: str = "Chapa", **kw: object) -> ProductInput:
    base: dict[str, object] = {"name": name, "category": "MP", "quantity": 10, "min_quantity": 5, "unit": "Unidade"}
    base.update(kw)
    return ProductInput(**base)  # type: ignore[arg-type]


def _actions(repo: Repository) -> list[str]:
    return [r["action"] for r in repo.list_audit()]


def test_bootstrap_admin_generates_password_once(db_path: Path) -> None:
    with open_db(db_path) as conn:
        init_schema(conn)
        generated = bootstrap_admin(conn, "root", None)
        assert generated
        assert bootstrap_admin(conn, "root", None) is None
        repo = Repository(conn)
        user = repo.authenticate("root", generated)
        assert user is not None
        assert user.access_level == "Administrador"


def test_authenticate(repo: Repository) -> None:
    assert repo.authenticate("admin", "errada-123") is None
    assert repo.authenticate("ninguem", ADMIN_PASSWORD) is None
    assert repo.authenticate(" admin ", ADMIN_PASSWORD) is not None


def test_legacy_hash_is_accepted_and_upgraded(repo: Repository) -> None:
    salt = bytes(range(16))
    legacy = hashlib.sha256(salt + b"oper123").hexdigest()
    repo.conn.execute(
        "INSERT INTO users (username, password, name, access_level, salt) VALUES ('oper', ?, 'Op', 'Operacional', ?)",
        (legacy, salt.hex()),
    )
    repo.conn.commit()
    assert repo.authenticate("oper", "oper123") is not None
    stored = repo.conn.execute("SELECT password FROM users WHERE username = 'oper'").fetchone()[0]
    assert stored.startswith("pbkdf2_sha256$")
    assert repo.authenticate("oper", "oper123") is not None


def test_invalid_legacy_salt_does_not_crash(repo: Repository) -> None:
    # O seed da versão 1.0 gravava salt 'salt_hex_value', que derrubava o login.
    repo.conn.execute(
        "INSERT INTO users (username, password, name, access_level, salt) VALUES ('x', 'abc', 'X', 'CEO', 'salt_hex_value')"
    )
    repo.conn.commit()
    assert repo.authenticate("x", "admin") is None


def test_product_crud_with_audit(repo: Repository) -> None:
    admin = _admin(repo)
    pid = repo.create_product(admin, _product(quantity=0, min_quantity=0, expiry_date=TODAY + timedelta(days=10)))
    row = repo.get_product(pid)
    assert row is not None
    assert row["quantity"] == 0
    assert row["expiry_date"] == "2026-03-25"
    repo.update_product(admin, pid, _product("Chapa 2mm", quantity=3))
    row = repo.get_product(pid)
    assert row is not None
    assert row["name"] == "Chapa 2mm"
    assert row["expiry_date"] is None
    repo.add_qc(admin, pid, TODAY, 5, 2.0, 0.1, 0.05)
    repo.delete_product(admin, pid)
    assert repo.get_product(pid) is None
    assert repo.qc_rows(pid) == []
    assert {"PRODUCT_CREATE", "PRODUCT_UPDATE", "QC_CREATE", "PRODUCT_DELETE"} <= set(_actions(repo))


def test_product_validation_is_enforced_in_repository(repo: Repository) -> None:
    with pytest.raises(ValidationError):
        repo.create_product(_admin(repo), _product(name=""))
    with pytest.raises(LookupError):
        repo.update_product(_admin(repo), 999, _product())
    with pytest.raises(LookupError):
        repo.delete_product(_admin(repo), 999)


def test_list_products_filters(repo: Repository) -> None:
    admin = _admin(repo)
    repo.create_product(admin, _product("Sem validade", quantity=1, min_quantity=5))
    repo.create_product(admin, _product("Vencido", expiry_date=TODAY - timedelta(days=1)))
    repo.create_product(admin, _product("Proximo", expiry_date=TODAY + timedelta(days=5)))
    repo.create_product(admin, _product("Longe", expiry_date=TODAY + timedelta(days=200)))

    def names(**kw: str) -> list[str]:
        return [r["name"] for r in repo.list_products(TODAY, 30, **kw)]  # type: ignore[arg-type]

    assert names(stock="Crítico") == ["Sem validade"]
    assert names(stock="Normal") == ["Longe", "Proximo", "Vencido"]
    assert names(expiry="Válidos") == ["Longe", "Proximo", "Sem validade"]
    assert names(expiry="Vencidos") == ["Vencido"]
    assert names(expiry="Próximos da Validade") == ["Proximo"]
    assert names(category="Outra") == []


def test_dashboard_counts_include_overdue_tasks(repo: Repository) -> None:
    admin = _admin(repo)
    repo.create_task(admin, "Atrasada", "desc", admin, "Alta", TODAY - timedelta(days=3))
    repo.create_task(admin, "Futura", "desc", admin, "Baixa", TODAY + timedelta(days=3))
    repo.create_task(admin, "Sem prazo", "desc", admin, "Baixa", None)
    counts = repo.dashboard_counts(admin, TODAY, 30)
    assert counts["pending_tasks"] == 3
    overdue = repo.tasks(TODAY, assigned_to=admin, status="Atrasada")
    assert [t["title"] for t in overdue] == ["Atrasada"]
    # Ordenação: com prazo primeiro, sem prazo por último.
    assert [t["title"] for t in repo.tasks(TODAY)] == ["Atrasada", "Futura", "Sem prazo"]


def test_critical_products_handles_zero_minimum(repo: Repository) -> None:
    admin = _admin(repo)
    repo.create_product(admin, _product("Zero", quantity=0, min_quantity=0))
    repo.create_product(admin, _product("Metade", quantity=5, min_quantity=10))
    rows = repo.critical_products()
    assert [r["name"] for r in rows] == ["Metade", "Zero"]
    assert rows[0]["pct"] == pytest.approx(50.0)
    assert rows[1]["pct"] is None


def _second_user(repo: Repository, username: str = "op") -> int:
    return repo.create_user(None, username, hash_password("Senha-op-1"), "Operador", "", "Operacional")


def test_task_completion_respects_ownership(repo: Repository) -> None:
    admin = _admin(repo)
    op = _second_user(repo)
    task_id = repo.create_task(admin, "T", "d", admin, "Alta", None)
    assert not repo.complete_task(op, task_id)
    assert repo.complete_task(op, task_id, any_task=True)
    assert not repo.complete_task(admin, task_id)  # já concluída
    with pytest.raises(ValueError, match="obrigatórios"):
        repo.create_task(admin, " ", "d", op, "Alta", None)
    with pytest.raises(LookupError):
        repo.create_task(admin, "T", "d", 999, "Alta", None)


def test_messages(repo: Repository) -> None:
    admin = _admin(repo)
    op = _second_user(repo)
    repo.send_message(admin, op, "Oi", "Conteúdo")
    inbox = repo.inbox(op, read=False)
    assert len(inbox) == 1
    msg_id = inbox[0]["id"]
    assert not repo.mark_read(msg_id, admin)  # não é o destinatário
    assert repo.mark_read(msg_id, op)
    assert repo.inbox(op, read=False) == []
    assert len(repo.sent(admin)) == 1
    with pytest.raises(ValueError, match="si mesmo"):
        repo.send_message(admin, admin, "a", "b")
    with pytest.raises(ValueError, match="obrigatórios"):
        repo.send_message(admin, op, "", "b")
    with pytest.raises(LookupError):
        repo.send_message(admin, 999, "a", "b")


def test_deleted_user_keeps_history(repo: Repository) -> None:
    admin = _admin(repo)
    op = _second_user(repo)
    repo.send_message(op, admin, "Oi", "msg")
    repo.delete_user(admin, op)
    assert repo.inbox(admin)[0]["sender"] == "(usuário removido)"
    assert repo.get_user(op) is None


def test_user_update_and_unique_username(repo: Repository) -> None:
    admin = _admin(repo)
    op = _second_user(repo)
    repo.update_user(admin, op, "op2", "Operador 2", "op@x.com", "Supervisor", hash_password("Nova-senha-9"))
    assert repo.authenticate("op2", "Nova-senha-9") is not None
    with pytest.raises(sqlite3.IntegrityError):
        repo.update_user(admin, op, "admin", "x", "", "Supervisor")
    assert repo.count_admins() == 1


def test_app_settings_roundtrip(repo: Repository) -> None:
    assert repo.get_app_settings() == {"expiry_warning_days": 30, "default_min_quantity": 5}
    repo.save_app_settings(_admin(repo), {"expiry_warning_days": 15, "default_min_quantity": 2})
    assert repo.get_app_settings() == {"expiry_warning_days": 15, "default_min_quantity": 2}
    with pytest.raises(KeyError):
        repo.save_app_settings(_admin(repo), {"email": 1})


def test_add_qc_validation(repo: Repository) -> None:
    admin = _admin(repo)
    with pytest.raises(LookupError):
        repo.add_qc(admin, 999, TODAY, 5, 1.0, 0.1, 0.1)
    pid = repo.create_product(admin, _product())
    with pytest.raises(ValueError, match="negativos"):
        repo.add_qc(admin, pid, TODAY, 5, 1.0, -0.1, 0.1)


def test_backup_is_valid_sqlite(repo: Repository, tmp_path: Path) -> None:
    repo.create_product(_admin(repo), _product())
    target = tmp_path / "copy.db"
    target.write_bytes(repo.backup_bytes())
    with closing(sqlite3.connect(target)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 1


def test_schema_upgrade_on_legacy_database(db_path: Path) -> None:
    # Banco da versão 1.0: sem app_settings nem índices.
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, name TEXT, email TEXT, access_level TEXT, salt TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute(
            "INSERT INTO users (username, password, name, access_level, salt) VALUES ('admin', 'x', 'A', 'Administrador', '00')"
        )
    with open_db(db_path) as conn:
        init_schema(conn)
        assert bootstrap_admin(conn, "admin", None) is None
        assert Repository(conn).get_app_settings()["expiry_warning_days"] == 30


def test_seed_is_idempotent(repo: Repository) -> None:
    first = seed.seed(repo.conn, today=TODAY, demo_password="Demo-senha-1", rng=random.Random(1))
    assert first == {"users": 4, "products": 6, "qc": 50, "tasks": 2, "messages": 1}
    second = seed.seed(repo.conn, today=TODAY, demo_password="Demo-senha-1", rng=random.Random(1))
    assert second == {"users": 0, "products": 0, "qc": 0, "tasks": 0, "messages": 0}
    assert repo.authenticate("supervisor", "Demo-senha-1") is not None


def test_seed_cli(db_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("LINHAMESTRE_DB_PATH", str(db_path))
    monkeypatch.delenv("LINHAMESTRE_ADMIN_PASSWORD", raising=False)
    assert seed.main(["--random-seed", "3"]) == 0
    out = capsys.readouterr().out
    assert "senha gerada" in out
    with open_db(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 6
