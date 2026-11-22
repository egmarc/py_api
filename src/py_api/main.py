from fastapi import FastAPI

from py_api.api.router import api_router
from py_api.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=settings.version, debug=settings.debug)
    app.include_router(api_router)
    return app


app = create_app()
