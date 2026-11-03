#!/usr/bin/env python3
"""
Grant or revoke a GLOBAL role on an existing account, without the API.

Needed to bootstrap an SSO-only deployment: new accounts hold no role
(DEFAULT_USER_ROLE=none) and the role-management API is itself guarded by a role,
so the first administrator has to be created from outside the API. Prefer this over
promote_superuser.py: `admin` holds every permission and is revocable through the
API, while is_superuser bypasses the permission model entirely.

Usage:
    PYTHONPATH=. python3 scripts/grant_role.py --list
    PYTHONPATH=. python3 scripts/grant_role.py --username someone --role admin
    PYTHONPATH=. python3 scripts/grant_role.py --username someone --role admin --revoke

Which database is written is decided by SQLALCHEMY_DATABASE_URI. The tier and a
masked database URI are echoed and must be confirmed (--yes skips the prompt).
The role catalog must already be seeded (scripts/seed_rbac_catalog.py).
"""

import argparse
import getpass
import logging
import sys

from fastapi import HTTPException
from sqlmodel import Session, select

sys.path.insert(0, ".")

from api.auth.models import User  # noqa: E402
from api.rbac.models import Role, RoleScope, UserRole  # noqa: E402
from api.rbac.services import grant_global_role, revoke_global_role  # noqa: E402
from core.config import get_settings  # noqa: E402
from core.db import engine  # noqa: E402

from scripts.create_service_account import _mask_uri, confirm_target  # noqa: E402

logger = logging.getLogger("grant_role")


def holders(session: Session, role: Role) -> list[str]:
    return sorted(session.exec(
        select(User.username).join(UserRole, UserRole.user_id == User.id)
        .where(UserRole.role_id == role.id)
    ).all())


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--username", help="Account to change")
    ap.add_argument("--role", default="admin", help="Global role name (default admin)")
    ap.add_argument("--revoke", action="store_true", help="Remove the role instead")
    ap.add_argument("--list", action="store_true",
                    help="Print who holds the role and exit")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="Skip the tier confirmation prompt")
    args = ap.parse_args()

    if not args.list and not args.username:
        ap.error("--username is required unless --list is given")

    settings = get_settings()
    print(f"tier:     {settings.ENVIRONMENT}")
    print(f"database: {_mask_uri(settings.SQLALCHEMY_DATABASE_URI)}")
    print()

    with Session(engine) as session:
        role = session.exec(select(Role).where(Role.name == args.role)).first()
        if role is None:
            raise SystemExit(
                f"error: no role {args.role!r}. Seed the catalog first "
                f"(scripts/seed_rbac_catalog.py).")
        if role.scope is not RoleScope.GLOBAL:
            raise SystemExit(f"error: {role.name} is a project role, not a global one")

        before = holders(session, role)
        print(f"{role.name} holders now ({len(before)}): {', '.join(before) or '(none)'}")
        if args.list:
            return 0

        user = session.exec(select(User).where(User.username == args.username)).first()
        if user is None:
            raise SystemExit(
                f"error: no user {args.username!r} in this database. Check the tier "
                f"printed above, and that the account has signed in at least once.")

        verb = "revoke" if args.revoke else "grant"
        action = f"{verb} role {role.name} {'from' if args.revoke else 'to'} {user.username}"
        print()
        if args.dry_run:
            print(f"dry run: would {action}")
            return 0
        confirm_target(settings, action, args.yes)

        try:
            if args.revoke:
                revoke_global_role(session, user, role, acting_user_id=None)
                changed = True
            else:
                changed = grant_global_role(session, user, role, granted_by=None)
        except HTTPException as exc:  # e.g. refusing to remove the last role manager
            raise SystemExit(f"error: {exc.detail}")

        logger.warning("role %s %s for %s by operator %s (changed=%s)",
                       role.name, "revoked" if args.revoke else "granted",
                       user.username, getpass.getuser(), changed)
        after = holders(session, role)
        print(f"\n{role.name} holders now ({len(after)}): {', '.join(after) or '(none)'}")
        if not changed:
            print("(no change: the account already had that state)")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    raise SystemExit(main())
