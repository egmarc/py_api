from fastapi import APIRouter

from py_api.api.routes import auth, health, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.build_router(admin=False))
api_router.include_router(users.build_router(admin=True), prefix="/admin")
