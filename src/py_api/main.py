from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html

from py_api.api.router import api_router
from py_api.api.security import get_principal, https_url
from py_api.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name, version=settings.version, debug=settings.debug,
        openapi_url=None, docs_url=None, redoc_url=None,
    )

    @app.middleware("http")
    async def prevent_sensitive_caching(request, call_next):
        response = await call_next(request)
        if request.url.path != "/health-check":
            response.headers["Cache-Control"] = "no-store"
        return response

    if settings.frontend_origin:
        if not https_url(settings.frontend_origin, origin_only=True):
            raise RuntimeError("PY_API_FRONTEND_ORIGIN must be an HTTPS origin")
        app.add_middleware(
            CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )
    app.include_router(api_router)

    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(get_principal)])
    def openapi():
        return app.openapi()

    @app.get("/docs", include_in_schema=False, dependencies=[Depends(get_principal)])
    def docs():
        return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - Swagger UI")

    @app.get("/redoc", include_in_schema=False, dependencies=[Depends(get_principal)])
    def redoc():
        return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} - ReDoc")

    return app


app = create_app()
