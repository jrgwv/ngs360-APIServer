"""Tests for scripts/grant_role.py (first-administrator bootstrap for SSO-only tiers)."""
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from api.auth.models import User
from api.rbac.seed import sync_rbac_catalog
from scripts import grant_role as script


@pytest.fixture(name="session")
def session_fixture(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(script, "engine", engine)
    monkeypatch.setattr(script, "confirm_target", lambda *a, **k: None)
    with Session(engine) as s:
        sync_rbac_catalog(s)
        s.add(User(username="AmazonFederate_me", email=None, is_active=True,
                   is_verified=True))
        s.commit()
        yield s
    engine.dispose()


def run(monkeypatch, *argv):
    monkeypatch.setattr(script.sys, "argv", ["grant_role.py", *argv])
    return script.main()


def holders(session, role="admin"):
    from sqlmodel import select
    from api.rbac.models import Role
    session.expire_all()
    r = session.exec(select(Role).where(Role.name == role)).one()
    return script.holders(session, r)


def test_grants_the_admin_role_to_an_account_with_no_email(session, monkeypatch):
    assert run(monkeypatch, "--username", "AmazonFederate_me") == 0
    assert holders(session) == ["AmazonFederate_me"]


def test_grant_is_idempotent(session, monkeypatch, capsys):
    run(monkeypatch, "--username", "AmazonFederate_me")
    run(monkeypatch, "--username", "AmazonFederate_me")
    assert holders(session) == ["AmazonFederate_me"]
    assert "no change" in capsys.readouterr().out


def test_revoke_with_another_holder(session, monkeypatch):
    session.add(User(username="second", email=None, is_active=True, is_verified=True))
    session.commit()
    run(monkeypatch, "--username", "AmazonFederate_me")
    run(monkeypatch, "--username", "second")
    run(monkeypatch, "--username", "AmazonFederate_me", "--revoke")
    assert holders(session) == ["second"]


def test_the_last_administrator_cannot_be_revoked(session, monkeypatch):
    run(monkeypatch, "--username", "AmazonFederate_me")
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, "--username", "AmazonFederate_me", "--revoke")
    assert "error" in str(exc.value)
    assert holders(session) == ["AmazonFederate_me"]


def test_dry_run_changes_nothing(session, monkeypatch):
    run(monkeypatch, "--username", "AmazonFederate_me", "--dry-run")
    assert holders(session) == []


def test_unknown_user_and_unknown_role_exit_with_an_error(session, monkeypatch):
    with pytest.raises(SystemExit):
        run(monkeypatch, "--username", "nobody")
    with pytest.raises(SystemExit):
        run(monkeypatch, "--username", "AmazonFederate_me", "--role", "no_such_role")


def test_list_reports_holders(session, monkeypatch, capsys):
    run(monkeypatch, "--username", "AmazonFederate_me")
    run(monkeypatch, "--list")
    assert "AmazonFederate_me" in capsys.readouterr().out
