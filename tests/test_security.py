import hashlib

import pytest

from linhamestre import security


def test_hash_and_verify_roundtrip() -> None:
    ph = security.hash_password("Senha-forte-1", iterations=1000)
    assert ph.hashed.startswith("pbkdf2_sha256$1000$")
    assert security.verify_password("Senha-forte-1", ph.hashed, ph.salt)
    assert not security.verify_password("errada", ph.hashed, ph.salt)


def test_salts_are_unique() -> None:
    a = security.hash_password("x", iterations=1000)
    b = security.hash_password("x", iterations=1000)
    assert a.salt != b.salt
    assert a.hashed != b.hashed


def test_verify_legacy_sha256_hash() -> None:
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    legacy = hashlib.sha256(salt + b"admin123").hexdigest()
    assert security.verify_password("admin123", legacy, salt.hex())
    assert not security.verify_password("admin1234", legacy, salt.hex())
    assert security.needs_rehash(legacy)


@pytest.mark.parametrize(
    ("stored_hash", "salt"),
    [(None, "00"), ("abc", None), ("abc", "salt_hex_value"), ("pbkdf2_sha256$x$y", "00")],
)
def test_verify_rejects_malformed(stored_hash: str | None, salt: str | None) -> None:
    assert not security.verify_password("qualquer", stored_hash, salt)


def test_needs_rehash_for_low_iterations() -> None:
    assert security.needs_rehash(f"pbkdf2_sha256${security.PBKDF2_ITERATIONS - 1}$aa")
    assert not security.needs_rehash(f"pbkdf2_sha256${security.PBKDF2_ITERATIONS}$aa")


def test_password_problems() -> None:
    assert security.password_problems("curta1") != []
    assert security.password_problems("somenteletras") != []
    assert security.password_problems("12345678901") != []
    assert security.password_problems(" comespaco1") != []
    assert security.password_problems("boa-senha-42") == []


def test_generate_password_passes_policy() -> None:
    for _ in range(20):
        assert security.password_problems(security.generate_password()) == []


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_login_throttle_locks_and_expires() -> None:
    clock = FakeClock()
    throttle = security.LoginThrottle(max_attempts=3, lockout_seconds=60, clock=clock)
    assert not throttle.register_failure("Admin")
    assert not throttle.register_failure("admin ")
    assert throttle.register_failure("ADMIN")
    assert throttle.seconds_locked("admin") == pytest.approx(60)
    assert throttle.seconds_locked("outro") == 0
    clock.now += 61
    assert throttle.seconds_locked("admin") == 0
    assert not throttle.register_failure("admin")


def test_login_throttle_success_resets() -> None:
    throttle = security.LoginThrottle(max_attempts=2, lockout_seconds=60, clock=FakeClock())
    throttle.register_failure("u")
    throttle.register_success("u")
    assert not throttle.register_failure("u")
