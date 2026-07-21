from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.model_loader import load_model
from app.api.routes.auth import router as auth_router
from app.api.routes.scan import router as scan_router
from app.core.logger import logger
from app.exceptions.handlers import register_exception_handlers
from app.core.config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting application...")
    load_model()
    logger.info("Application startup completed.")

    yield

    logger.info("Application shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

register_exception_handlers(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    auth_router,
    prefix="/api/v1",
)
app.include_router(scan_router)