"""Testes de integração da interface com ``streamlit.testing`` (sem navegador)."""

import random
from collections.abc import Iterator
from datetime import date
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from linhamestre import app as app_module
from linhamestre import seed
from linhamestre.db import Repository, bootstrap_admin, init_schema, open_db
from linhamestre.domain import ProductInput

from .conftest import ADMIN_PASSWORD

ENTRY = str(Path(__file__).resolve().parents[1] / "linhamestre_app.py")
DEMO_PASSWORD = "Demo-senha-1"


@pytest.fixture
def app_db(db_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("LINHAMESTRE_DB_PATH", str(db_path))
    monkeypatch.setenv("LINHAMESTRE_ADMIN_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.setenv("LINHAMESTRE_MAX_LOGIN_ATTEMPTS", "3")
    with open_db(db_path) as conn:
        init_schema(conn)
        bootstrap_admin(conn, "admin", ADMIN_PASSWORD)
        seed.seed(conn, today=date.today(), demo_password=DEMO_PASSWORD, rng=random.Random(7))
    app_module.boot.clear()
    yield db_path
    app_module.boot.clear()


def _run(at: AppTest) -> AppTest:
    at.run(timeout=30)
    assert not at.exception, [e.message for e in at.exception]
    return at


def _login(username: str, password: str) -> AppTest:
    at = _run(AppTest.from_file(ENTRY, default_timeout=30))
    at.text_input[0].input(username)
    at.text_input[1].input(password)
    at.button[0].click()
    return _run(at)


def _go(at: AppTest, page: str) -> AppTest:
    at.sidebar.radio[0].set_value(page)
    return _run(at)


def _menu(at: AppTest) -> list[str]:
    # As opções exibidas trazem o ícone antes do nome: ":material/x: Nome".
    return [str(o).split(" ", 1)[1] for o in at.sidebar.radio[0].options]


def _texts(at: AppTest) -> str:
    parts = [m.value for m in at.markdown] + [e.value for e in at.error] + [s.value for s in at.success]
    parts += [w.value for w in at.warning] + [i.value for i in at.info] + [t.value for t in at.title]
    return "\n".join(str(p) for p in parts)


@pytest.mark.usefixtures("app_db")
def test_login_rejects_wrong_password() -> None:
    at = _login("admin", "errada-123")
    assert "Usuário ou senha incorretos." in [e.value for e in at.error]


@pytest.mark.usefixtures("app_db")
def test_login_lockout_after_repeated_failures() -> None:
    for _ in range(3):
        _login("admin", "errada-123")
    at = _login("admin", ADMIN_PASSWORD)
    assert any("Muitas tentativas" in e.value for e in at.error)


@pytest.mark.usefixtures("app_db")
def test_admin_can_open_every_page() -> None:
    at = _login("admin", ADMIN_PASSWORD)
    assert at.title[0].value == "Dashboard"
    pages = _menu(at)
    assert pages == [
        "Dashboard",
        "Produtos",
        "Mensagens",
        "Tarefas",
        "Controle de Qualidade",
        "Usuários",
        "Configurações",
    ]
    for page in pages:
        _go(at, page)
    _go(at, "Controle de Qualidade")
    selector = at.selectbox(key="qc_product_selector")
    selector.set_value(next(o for o in selector.options if o.startswith("Chapa")))
    _run(at)
    assert "Sinais de instabilidade" in _texts(at) or "sob controle" in _texts(at)


@pytest.mark.usefixtures("app_db")
def test_operational_user_has_restricted_menu() -> None:
    at = _login("operacional", DEMO_PASSWORD)
    assert _menu(at) == ["Dashboard", "Produtos", "Mensagens", "Tarefas"]
    _go(at, "Produtos")
    assert "Você não tem permissão para adicionar produtos." in [w.value for w in at.warning]


def test_user_content_is_escaped(app_db: Path) -> None:
    with open_db(app_db) as conn:
        repo = Repository(conn)
        admin = repo.authenticate("admin", ADMIN_PASSWORD)
        assert admin is not None
        repo.create_product(
            admin.id,
            ProductInput(name="[clique](https://evil.example)", category="X", quantity=0, min_quantity=1, unit="Kg"),
        )
    at = _login("admin", ADMIN_PASSWORD)
    rendered = _texts(at)
    assert "\\[clique\\]\\(https\\:" in rendered
    assert "[clique](https://evil.example)" not in rendered


@pytest.mark.usefixtures("app_db")
def test_session_drops_when_user_is_deleted(app_db: Path) -> None:
    at = _login("supervisor", DEMO_PASSWORD)
    assert at.title[0].value == "Dashboard"
    with open_db(app_db) as conn:
        conn.execute("DELETE FROM users WHERE username = 'supervisor'")
        conn.commit()
    _run(at)
    assert at.title[0].value == "LinhaMestre"


@pytest.mark.usefixtures("app_db")
def test_settings_are_persisted(app_db: Path) -> None:
    at = _go(_login("admin", ADMIN_PASSWORD), "Configurações")
    at.number_input[1].set_value(10)
    at.button[0].click()
    _run(at)
    with open_db(app_db) as conn:
        assert Repository(conn).get_app_settings()["expiry_warning_days"] == 10


@pytest.mark.usefixtures("app_db")
def test_supervisor_creates_product_with_zero_stock(app_db: Path) -> None:
    at = _go(_login("supervisor", DEMO_PASSWORD), "Produtos")
    form = next(t for t in at.text_input if t.label == "Nome do produto *")
    form.input("Luva nitrílica")
    next(t for t in at.text_input if t.label == "Categoria *").input("EPI")
    at.button(key="add_0_submit").click()
    _run(at)
    assert any("Luva nitrílica" in s.value for s in at.success)
    with open_db(app_db) as conn:
        row = conn.execute("SELECT quantity FROM products WHERE name = 'Luva nitrílica'").fetchone()
        assert row["quantity"] == 0
        actions = [r[0] for r in conn.execute("SELECT action FROM audit_logs")]
        assert "PRODUCT_CREATE" in actions


@pytest.mark.usefixtures("app_db")
def test_send_message_between_users(app_db: Path) -> None:
    at = _go(_login("gerente", DEMO_PASSWORD), "Mensagens")
    next(t for t in at.text_input if t.label == "Assunto *").input("Inventário")
    next(t for t in at.text_area if t.label == "Mensagem *").input("Conferir setor B.")
    at.button(key="FormSubmitter:send_message_form-Enviar mensagem").click()
    _run(at)
    assert "Mensagem enviada com sucesso." in [s.value for s in at.success]
    with open_db(app_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM messages WHERE subject = 'Inventário'").fetchone()[0] == 1


@pytest.mark.usefixtures("app_db")
def test_admin_user_creation_enforces_password_policy(app_db: Path) -> None:
    at = _go(_login("admin", ADMIN_PASSWORD), "Usuários")
    next(t for t in at.text_input if t.label == "Nome de usuário *").input("novo.usuario")
    next(t for t in at.text_input if t.label == "Senha *").input("123")
    next(t for t in at.text_input if t.label == "Nome completo *").input("Novo Usuário")
    at.button(key="FormSubmitter:add_user_form-Cadastrar usuário").click()
    _run(at)
    assert any("pelo menos 8" in e.value for e in at.error)
    with open_db(app_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE username = 'novo.usuario'").fetchone()[0] == 0
