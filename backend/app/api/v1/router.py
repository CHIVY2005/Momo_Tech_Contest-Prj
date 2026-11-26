"""Aggregated v1 API router exposing all 11 VeriShield AI endpoints."""

from fastapi import APIRouter

from app.api.v1 import analyze, cases, health, radar, telegram

v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(health.router)
v1_router.include_router(analyze.router)
v1_router.include_router(cases.router)
v1_router.include_router(radar.router)
v1_router.include_router(telegram.router)
