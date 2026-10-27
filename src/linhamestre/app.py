"""Ponto de entrada Streamlit: boot, autenticação e navegação."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import streamlit as st

from . import __version__
from .config import ConfigError, Settings, load_settings
from .db import Repository, User, bootstrap_admin, init_schema, open_db
from .domain import AccessLevel, has_permission
from .logging_setup import configure_logging
from .security import LoginThrottle
from .ui import dashboard, messages, products, quality, settings_page, tasks, users
from .ui.common import Context, md

log = logging.getLogger("linhamestre.app")

STYLES_PATH = Path(__file__).with_name("styles.css")
SESSION_KEYS = ("user_id",)


@dataclass(frozen=True, slots=True)
class Runtime:
    settings: Settings
    throttle: LoginThrottle


@st.cache_resource(show_spinner=False)
def boot() -> Runtime:
    """Executa uma vez por processo: valida configuração, cria esquema e admin inicial."""
    settings = load_settings()
    configure_logging(settings.log_level, settings.log_format)
    with open_db(settings.db_path) as conn:
        init_schema(conn)
        generated = bootstrap_admin(conn, settings.admin_username, settings.admin_password)
    if generated:
        # Exibida apenas no log do processo, uma única vez, para o primeiro acesso.
        log.warning(
            "Administrador inicial criado com senha gerada. Altere-a após o primeiro acesso.",
            extra={"username": settings.admin_username, "password": generated},
        )
    log.info("app_started", extra={"db_path": str(settings.db_path), "version": __version__})
    return Runtime(settings, LoginThrottle(settings.max_login_attempts, settings.lockout_minutes * 60))


def _inject_css() -> None:
    try:
        st.html(f"<style>{STYLES_PATH.read_text(encoding='utf-8')}</style>")
    except OSError:
        log.warning("styles_not_found", extra={"path": str(STYLES_PATH)})


def _logout(repo: Repository, user: User | None) -> None:
    if user:
        repo.log_audit(user.id, "LOGOUT", f"Usuário {user.username} saiu do sistema.")
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()


def _login(repo: Repository, runtime: Runtime) -> None:
    _, center, _ = st.columns([1, 2, 1])
    with center:
        st.title("LinhaMestre")
        st.caption("Controle de qualidade e estoque")
        with st.form("login_form"):
            username = st.text_input("Usuário", max_chars=50, autocomplete="username")
            password = st.text_input("Senha", type="password", max_chars=128, autocomplete="current-password")
            submitted = st.form_submit_button("Entrar", type="primary", width="stretch")
        if not submitted:
            return
        username = username.strip()
        if not username or not password:
            st.error("Informe usuário e senha.")
            return
        remaining = runtime.throttle.seconds_locked(username)
        if remaining > 0:
            st.error(f"Muitas tentativas. Tente novamente em {int(remaining // 60) + 1} minuto(s).")
            return
        user = repo.authenticate(username, password)
        if user is None:
            locked = runtime.throttle.register_failure(username)
            repo.log_audit(None, "LOGIN_FAILED", f"Falha de login para '{username[:50]}'.")
            log.warning("login_failed", extra={"username": username[:50], "locked": locked})
            st.error("Usuário ou senha incorretos.")
            return
        runtime.throttle.register_success(username)
        repo.log_audit(user.id, "LOGIN", f"Usuário {user.username} entrou no sistema.")
        log.info("login_ok", extra={"user_id": user.id})
        st.session_state["user_id"] = user.id
        st.rerun()


PageFn = Callable[[Context], None]


def _pages(level: str) -> dict[str, tuple[str, PageFn]]:
    pages: dict[str, tuple[str, PageFn]] = {
        "Dashboard": (":material/dashboard:", dashboard.render),
        "Produtos": (":material/inventory_2:", products.render),
        "Mensagens": (":material/mail:", messages.render),
        "Tarefas": (":material/task_alt:", tasks.render),
    }
    if has_permission(level, AccessLevel.SUPERVISOR):
        pages["Controle de Qualidade"] = (":material/monitoring:", quality.render)
    if has_permission(level, AccessLevel.ADMINISTRADOR):
        pages["Usuários"] = (":material/group:", users.render)
    if has_permission(level, AccessLevel.GERENTE):
        pages["Configurações"] = (":material/settings:", settings_page.render)
    return pages


def main() -> None:
    st.set_page_config(page_title="LinhaMestre", page_icon=":material/insights:", layout="wide")
    _inject_css()
    try:
        runtime = boot()
    except ConfigError as exc:
        st.error(f"Configuração inválida: {exc}")
        st.stop()

    with open_db(runtime.settings.db_path) as conn:
        repo = Repository(conn)
        user_id = st.session_state.get("user_id")
        # Recarrega o usuário a cada execução: exclusões e mudanças de perfil valem na hora.
        user = repo.get_user(int(user_id)) if user_id is not None else None
        if user_id is not None and user is None:
            _logout(repo, None)
        if user is None:
            _login(repo, runtime)
            _footer()
            return

        app_settings = repo.get_app_settings()
        ctx = Context(
            repo=repo,
            user=user,
            settings=runtime.settings,
            today=datetime.now(runtime.settings.timezone).date(),
            warning_days=app_settings["expiry_warning_days"],
            default_min_quantity=app_settings["default_min_quantity"],
        )
        pages = _pages(user.access_level)
        with st.sidebar:
            st.markdown(f"**{md(user.name)}**  \n{md(user.access_level)}")
            selected = st.radio(
                "Navegação",
                list(pages),
                format_func=lambda name: f"{pages[name][0]} {name}",
                key="nav_page",
            )
            st.divider()
            if st.button("Sair", icon=":material/logout:", width="stretch"):
                _logout(repo, user)
        pages[selected][1](ctx)
        _footer()


def _footer() -> None:
    st.sidebar.caption(f"LinhaMestre v{__version__} · licença MIT")
