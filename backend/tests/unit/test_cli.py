import sys

import pytest

from dpmap import cli


class _ContextSession:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


def test_create_admin_cli_requires_database_url(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["dpmap", "create-admin", "--email", "a@b.test"])
    monkeypatch.delenv("APP_DB_URL", raising=False)
    with pytest.raises(SystemExit):
        cli.main()


def test_create_admin_cli_rejects_mismatched_passwords(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["dpmap", "create-admin", "--email", "a@b.test"])
    monkeypatch.setenv("APP_DB_URL", "postgresql+psycopg://localhost/example")
    answers = iter(("first-password-value", "second-password-value"))
    monkeypatch.setattr(cli, "getpass", lambda _: next(answers))
    with pytest.raises(SystemExit):
        cli.main()


def test_create_admin_cli_reads_password_from_hidden_prompt(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["dpmap", "create-admin", "--email", "a@b.test"])
    monkeypatch.setenv("APP_DB_URL", "postgresql+psycopg://localhost/example")
    password = "same-password-value"
    monkeypatch.setattr(cli, "getpass", lambda _: password)
    monkeypatch.setattr(cli, "create_engine", lambda _: object())
    monkeypatch.setattr(cli, "Session", lambda _: _ContextSession())
    received = []
    monkeypatch.setattr(
        cli,
        "bootstrap_admin",
        lambda session, email, supplied: received.append((email, supplied)),
    )

    cli.main()

    assert received == [("a@b.test", password)]
