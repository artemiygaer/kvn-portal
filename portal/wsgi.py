"""WSGI entrypoint портала."""

from app import create_app

application = create_app()
