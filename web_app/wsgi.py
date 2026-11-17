"""Entry point for gunicorn: `gunicorn wsgi:app`. Reads its configuration (and secrets) at start-up."""
from app import create_app
from settings import load_settings

app = create_app(load_settings())
