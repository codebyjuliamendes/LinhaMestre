from collections.abc import Iterator
from pathlib import Path

import pytest

from linhamestre import security
from linhamestre.db import Repository, bootstrap_admin, init_schema, open_db

ADMIN_PASSWORD = "Admin-teste-123"


@pytest.fixture(autouse=True)
def fast_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """PBKDF2 com poucas iterações para manter a suíte rápida."""
    monkeypatch.setattr(security, "PBKDF2_ITERATIONS", 1000)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "linhamestre.db"


@pytest.fixture
def repo(db_path: Path) -> Iterator[Repository]:
    with open_db(db_path) as conn:
        init_schema(conn)
        bootstrap_admin(conn, "admin", ADMIN_PASSWORD)
        yield Repository(conn)
