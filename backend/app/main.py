from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.model_loader import load_model
from app.api.routes.health import router as health_router
from app.api.routes.scan import router as scan_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once when the application starts.
    """

    load_model()

    yield

    print("Application shutting down...")


app = FastAPI(
    title="Phishing Guardian API",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(scan_router)