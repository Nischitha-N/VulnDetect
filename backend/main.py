"""
Main FastAPI application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.api.routes import router
from app.ml.predictor import get_ml_predictor


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up ML verification model at startup (not on first request)
    print("Warming up ML verification model...")
    get_ml_predictor()
    print("ML verification model ready.")
    yield


app = FastAPI(
    title="VulnDetect API",
    description="Multi-layer static analysis engine with auxiliary ML finding-level verification for C/C++",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
async def root():
    return {"message": "VulnDetect Static Analysis & Verification API", "docs": "/docs"}
