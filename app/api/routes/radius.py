"""
RADIUS API Routes
Authentication testing endpoints
"""

from fastapi import APIRouter, HTTPException
from app.models import RADIUSTestRequest, RADIUSTestResponse
from app.services.docker_executor import docker_executor
from datetime import datetime
import logging
import re

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/test", response_model=RADIUSTestResponse)
async def test_radius_auth(request: RADIUSTestRequest):
    """
    Test RADIUS authentication
    
    Test user credentials against the RADIUS server.
    Uses radtest command from scanner container.
    
    Example users (configured in RADIUS):
    - testuser1 / test123
    - testuser2 / test456
    - admin / admin123
    """
    try:
        # Build radtest command
        # radtest username password server[:port] nas-port-number secret
        command = [
            "radtest",
            request.username,
            request.password,
            "10.0.1.10",  # RADIUS server IP
            "0",          # NAS port number
            "testing123"  # Shared secret
        ]
        
        logger.info(f"Testing RADIUS authentication for user: {request.username}")
        
        # Execute radtest in scanner container
        success, output = docker_executor.exec_network_command(
            command=command,
            timeout=10
        )
        
        if not success:
            logger.error(f"radtest command failed: {output}")
            return RADIUSTestResponse(
                success=False,
                username=request.username,
                server="10.0.1.10",
                authenticated=False,
                message="RADIUS test command failed",
                response_time=0.0,
                raw_output=output
            )
        
        # Parse output for authentication result
        authenticated = "Access-Accept" in output
        rejected = "Access-Reject" in output
        
        # Extract response time if available
        response_time = 0.0
        time_match = re.search(r'rtt\s+(\d+\.\d+)', output)
        if time_match:
            response_time = float(time_match.group(1))
        
        # Determine message
        if authenticated:
            message = "Authentication successful"
        elif rejected:
            message = "Authentication failed - Invalid credentials"
        else:
            message = "RADIUS server did not respond"
        
        logger.info(f"RADIUS test result for {request.username}: {message}")
        
        return RADIUSTestResponse(
            success=True,
            username=request.username,
            server="10.0.1.10",
            authenticated=authenticated,
            message=message,
            response_time=response_time,
            raw_output=output
        )
        
    except Exception as e:
        logger.error(f"Error testing RADIUS authentication: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"RADIUS test failed: {str(e)}"
        )


@router.get("/status")
async def radius_status():
    """
    Get RADIUS server status
    
    Checks if RADIUS server container is running and accessible.
    """
    try:
        # Check container status
        status = docker_executor.get_container_status("noc_radius")
        
        if "error" in status:
            return {
                "success": False,
                "status": "unreachable",
                "message": status["error"]
            }
        
        # Check if we can reach RADIUS port
        port_check_cmd = ["nc", "-zv", "10.0.1.10", "1812"]
        reachable, _ = docker_executor.exec_network_command(
            command=port_check_cmd,
            timeout=5
        )
        
        return {
            "success": True,
            "status": status["status"],
            "reachable": reachable,
            "server": "10.0.1.10",
            "port": 1812,
            "container_health": status.get("health"),
            "message": "RADIUS server is operational" if reachable else "RADIUS server is not reachable"
        }
        
    except Exception as e:
        logger.error(f"Error checking RADIUS status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to check RADIUS status: {str(e)}"
        )


@router.get("/users")
async def list_radius_users():
    """
    List configured RADIUS test users
    
    Returns the list of test users configured in the RADIUS server.
    Note: In production, user lists should not be exposed via API.
    """
    # These are the test users from your RADIUS config
    users = [
        {
            "username": "testuser1",
            "description": "Test user 1",
            "password_hint": "test123"
        },
        {
            "username": "testuser2", 
            "description": "Test user 2",
            "password_hint": "test456"
        },
        {
            "username": "admin",
            "description": "Admin user",
            "password_hint": "admin123"
        }
    ]
    
    return {
        "success": True,
        "users": users,
        "count": len(users),
        "message": "These are test users for demonstration purposes"
    }