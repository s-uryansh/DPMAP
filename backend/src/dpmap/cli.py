"""Local administrative commands."""

import argparse
from getpass import getpass
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from dpmap.services.auth import bootstrap_admin


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m dpmap.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_admin = subparsers.add_parser("create-admin")
    create_admin.add_argument("--email", required=True)
    args = parser.parse_args()

    database_url = os.getenv("APP_DB_URL")
    if not database_url:
        parser.error("APP_DB_URL is required")
    password = getpass("Initial Admin password: ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        parser.error("passwords do not match")

    with Session(create_engine(database_url)) as session:
        bootstrap_admin(session, args.email, password)
    print("Initial Admin created.")


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    main()
