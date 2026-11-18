"""Entrypoint for Vercel (and any ASGI host): `app` is the FastAPI application."""
from fastapi import FastAPI

from workbench.main import create_app

app: FastAPI = create_app()
