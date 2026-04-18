"""
Main FastAPI application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.api.routes import router
from app.ml.model import get_model


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up ML model at startup (not on first request)
    print("Warming up ML model...")
    get_model()
    print("Model ready.")
    yield


app = FastAPI(
    title="AI Code Vulnerability Detector",
    description="Detect vulnerabilities in C/C++ code using static analysis + ML",
    version="1.0.0",
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
    return {"message": "AI Code Vulnerability Detector API", "docs": "/docs"}
