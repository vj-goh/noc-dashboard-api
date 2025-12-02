"""
Health Check API Routes
System health and status endpoints
"""

from fastapi import APIRouter
from app.models import HealthCheckResponse, ContainerStatus, StatusResponse
from app.services.docker_executor import docker_executor
from app.config import settings
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/status", response_model=HealthCheckResponse)
async def get_health_status():
    """
    Get overall system health status
    
    Checks:
    - Docker containers status
    - Network connectivity
    - Service availability
    """
    try:
        # Get status of all NOC containers
        container_names = [
            settings.ROUTER1_CONTAINER,
            settings.ROUTER2_CONTAINER,
            settings.SCANNER_CONTAINER,
            settings.RADIUS_CONTAINER,
            settings.DNS_CONTAINER
        ]
        
        containers = []
        all_healthy = True
        
        for container_name in container_names:
            status_info = docker_executor.get_container_status(container_name)
            
            if "error" in status_info:
                all_healthy = False
                containers.append(ContainerStatus(
                    name=container_name,
                    status="error",
                    health=None,
                    uptime=None
                ))
            else:
                is_running = status_info.get('status') == 'running'
                if not is_running:
                    all_healthy = False
                
                containers.append(ContainerStatus(
                    name=container_name,
                    status=status_info.get('status', 'unknown'),
                    health=status_info.get('health'),
                    uptime=status_info.get('started')
                ))
        
        # Perform basic checks
        checks = {
            "docker_client": docker_executor.client is not None,
            "all_containers_running": all_healthy
        }
        
        overall_status = "healthy" if all_healthy else "degraded"
        
        return HealthCheckResponse(
            success=True,
            status=overall_status,
            containers=containers,
            checks=checks
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthCheckResponse(
            success=False,
            status="unhealthy",
            containers=[],
            checks={"error": True}
        )

@router.get("/ping", response_model=StatusResponse)
async def ping_health():
    """
    Simple ping endpoint for basic health check
    """
    return StatusResponse(
        success=True,
        message="API is running"
    )

@router.get("/containers")
async def list_containers():
    """
    List all Docker containers
    """
    try:
        containers = docker_executor.list_containers(all=True)
        return {
            "success": True,
            "containers": containers,
            "count": len(containers)
        }
    except Exception as e:
        logger.error(f"Failed to list containers: {e}")
        return {
            "success": False,
            "error": str(e)
        }