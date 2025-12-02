"""
Configuration settings for NOC Dashboard API
Uses pydantic for settings management
"""

from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = True
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ]
    
    # Docker Configuration
    DOCKER_SOCKET: str = "/var/run/docker.sock"
    
    # Container Names
    ROUTER1_CONTAINER: str = "noc_router1"
    ROUTER2_CONTAINER: str = "noc_router2"
    SCANNER_CONTAINER: str = "noc_scanner"
    RADIUS_CONTAINER: str = "noc_radius"
    DNS_CONTAINER: str = "noc_dns"
    
    # Network Configuration
    CORE_NETWORK: str = "10.0.1.0/24"
    EDGE_NETWORK: str = "10.0.2.0/24"
    CLIENT_NETWORK: str = "10.0.3.0/24"
    
    # RADIUS Configuration
    RADIUS_SERVER: str = "10.0.1.10"
    RADIUS_PORT: int = 1812
    RADIUS_SECRET: str = "testing123"
    
    # Scan Configuration
    DEFAULT_PORT_RANGE: str = "1-1024"
    SCAN_TIMEOUT: int = 300  # seconds
    
    # Data Storage
    DATA_DIR: str = "/data"
    LOG_DIR: str = "/var/log/api"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create global settings instance
settings = Settings()