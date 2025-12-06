"""
Docker Executor Service
Handles execution of commands in Docker containers
"""

import docker
import logging
from typing import Tuple, Optional
import subprocess
from app.config import settings

logger = logging.getLogger(__name__)

class DockerExecutor:
    """Execute commands in Docker containers"""
    
    def __init__(self):
        """Initialize Docker client with explicit Unix socket"""
        self.client = None
        
        try:
            # Explicitly use Unix socket (works in containers)
            self.client = docker.DockerClient(base_url='unix://var/run/docker.sock')
            
            # Test the connection
            self.client.ping()
            logger.info("Docker client initialized successfully via Unix socket")
            
        except Exception as e:
            logger.warning("=" * 60)
            logger.warning("⚠️  Docker client initialization failed")
            logger.warning(f"Error: {e}")
            logger.warning("")
            logger.warning("The API will start, but Docker functionality won't work.")
            logger.warning("To fix this:")
            logger.warning("  1. Verify socket is mounted: docker exec noc_api ls -la /var/run/docker.sock")
            logger.warning("  2. Check docker-compose.yml has: /var/run/docker.sock:/var/run/docker.sock")
            logger.warning("  3. Check socket permissions: docker exec noc_api ls -la /var/run/docker.sock")
            logger.warning("=" * 60)
            self.client = None
    
    def exec_in_container(
        self,
        container_name: str,
        command: str | list,
        timeout: int = 30,
        workdir: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Execute a command in a Docker container
        
        Args:
            container_name: Name of the container
            command: Command to execute (string or list)
            timeout: Command timeout in seconds
            workdir: Working directory for command
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        if not self.client:
            return False, "", "Docker client not initialized"
        
        try:
            # Get container
            container = self.client.containers.get(container_name)
            
            # Check if container is running
            if container.status != 'running':
                logger.warning(f"Container {container_name} is not running: {container.status}")
                return False, "", f"Container is {container.status}"
            
            # Execute command
            logger.info(f"Executing in {container_name}: {command}")
            
            exec_result = container.exec_run(
                cmd=command,
                stdout=True,
                stderr=True,
                stream=False,
                workdir=workdir
            )
            
            stdout = exec_result.output.decode('utf-8') if exec_result.output else ""
            exit_code = exec_result.exit_code
            
            success = exit_code == 0
            
            if not success:
                logger.warning(f"Command failed with exit code {exit_code}: {stdout}")
            
            return success, stdout, ""
            
        except docker.errors.NotFound:
            logger.error(f"Container not found: {container_name}")
            return False, "", f"Container '{container_name}' not found"
        except Exception as e:
            logger.error(f"Error executing command in {container_name}: {e}")
            return False, "", str(e)
    
    def get_container_status(self, container_name: str) -> dict:
        """
        Get container status information
        
        Returns:
            Dictionary with container status details
        """
        if not self.client:
            return {"error": "Docker client not initialized"}
        
        try:
            container = self.client.containers.get(container_name)
            
            return {
                "name": container.name,
                "status": container.status,
                "health": container.attrs.get('State', {}).get('Health', {}).get('Status'),
                "created": container.attrs.get('Created'),
                "started": container.attrs.get('State', {}).get('StartedAt'),
                "image": container.image.tags[0] if container.image.tags else "unknown"
            }
        except docker.errors.NotFound:
            return {"error": f"Container '{container_name}' not found"}
        except Exception as e:
            logger.error(f"Error getting container status: {e}")
            return {"error": str(e)}
    
    def list_containers(self, all: bool = False) -> list:
        """
        List Docker containers
        
        Args:
            all: Include stopped containers
            
        Returns:
            List of container information dictionaries
        """
        if not self.client:
            return []
        
        try:
            containers = self.client.containers.list(all=all)
            
            return [{
                "name": c.name,
                "id": c.short_id,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else "unknown"
            } for c in containers]
        except Exception as e:
            logger.error(f"Error listing containers: {e}")
            return []
    
    def exec_vtysh_command(self, router: str, command: str) -> Tuple[bool, str]:
        """
        Execute a vtysh command on a router
        
        Args:
            router: Router name (router1 or router2)
            command: vtysh command to execute
            
        Returns:
            Tuple of (success, output)
        """
        container_name = getattr(settings, f"{router.upper()}_CONTAINER")
        
        # Format vtysh command
        vtysh_cmd = ["vtysh", "-c", command]
        
        success, stdout, stderr = self.exec_in_container(
            container_name=container_name,
            command=vtysh_cmd,
            timeout=10
        )
        
        return success, stdout if success else stderr
    
    def exec_network_command(self, command: list, timeout: int = 30) -> Tuple[bool, str]:
        """
        Execute a network diagnostic command in the scanner container
        
        Args:
            command: Command as list (e.g., ['ping', '-c', '3', '10.0.1.1'])
            timeout: Command timeout
            
        Returns:
            Tuple of (success, output)
        """
        success, stdout, stderr = self.exec_in_container(
            container_name=settings.SCANNER_CONTAINER,
            command=command,
            timeout=timeout
        )
        
        return success, stdout if success else stderr

# Create global instance
docker_executor = DockerExecutor()