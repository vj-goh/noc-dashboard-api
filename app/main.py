"""
NOC Dashboard API - Main Application
FastAPI backend for network operations center dashboard
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from app.api.routes import diagnostics, health # network, scan, radius,
from app.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="NOC Dashboard API",
    description="Network Operations Center monitoring and diagnostics API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api/health", tags=["Health"])
app.include_router(diagnostics.router, prefix="/api/diagnostics", tags=["Diagnostics"])
# app.include_router(network.router, prefix="/api/network", tags=["Network"])
# app.include_router(scan.router, prefix="/api/scan", tags=["Scanning"])
# app.include_router(radius.router, prefix="/api/radius", tags=["RADIUS"])

@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    logger.info("NOC Dashboard API starting up...")
    logger.info(f"API running in {'DEBUG' if settings.DEBUG else 'PRODUCTION'} mode")

@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown"""
    logger.info("NOC Dashboard API shutting down...")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "NOC Dashboard API",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "operational"
    }

@app.get("/api")
async def api_root():
    """API root endpoint with available routes"""
    return {
        "message": "NOC Dashboard API v1.0.0",
        "endpoints": {
            "health": "/api/health",
            "diagnostics": "/api/diagnostics",
            "network": "/api/network",
            "scan": "/api/scan",
            "radius": "/api/radius"
        },
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        }
    }

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handle all unhandled exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "message": str(exc) if settings.DEBUG else "An error occurred"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )