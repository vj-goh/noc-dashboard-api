"""
Virtual Devices API Routes
Manages virtual networks, DHCP servers, and virtual devices
"""

from fastapi import APIRouter, HTTPException, Query
from app.services.virtual_infrastructure import virtual_infra_manager
from app.models import (
    CreateNetworkRequest, CreateDHCPServerRequest, CreateDeviceRequest,
    StartTrafficRequest, ManualIPAssignmentRequest, TrafficPattern,
    NetworkListResponse, DHCPServerListResponse, DeviceListResponse,
    DHCPLeasesResponse, TrafficPatternResponse, StatusResponse, DeviceType
)
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# ===== Network Management Endpoints =====

@router.post("/networks/create")
async def create_network(request: CreateNetworkRequest):
    """Create a new virtual network"""
    try:
        success, network, message = virtual_infra_manager.create_network(
            name=request.name,
            subnet=request.subnet,
            gateway=request.gateway,
            dns_servers=request.dns_servers
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "network": network.dict()
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error creating network: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/networks/list")
async def list_networks() -> NetworkListResponse:
    """List all virtual networks"""
    try:
        networks = virtual_infra_manager.list_networks()
        return NetworkListResponse(
            success=True,
            networks=networks,
            count=len(networks)
        )
    except Exception as e:
        logger.error(f"Error listing networks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/networks/{network_id}")
async def get_network(network_id: str):
    """Get a specific network"""
    try:
        network = virtual_infra_manager.get_network(network_id)
        if not network:
            raise HTTPException(status_code=404, detail="Network not found")
        
        return {
            "success": True,
            "network": network.dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting network: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/networks/{network_id}")
async def delete_network(network_id: str):
    """Delete a network"""
    try:
        success, message = virtual_infra_manager.delete_network(network_id)
        
        if success:
            return {
                "success": True,
                "message": message
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error deleting network: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ===== DHCP Server Endpoints =====

@router.post("/dhcp/create")
async def create_dhcp_server(request: CreateDHCPServerRequest):
    """Create a DHCP server for a network"""
    try:
        success, server, message = virtual_infra_manager.create_dhcp_server(
            network_id=request.network_id,
            range_start=request.range_start,
            range_end=request.range_end,
            lease_time=request.lease_time,
            gateway=request.gateway,
            dns_servers=request.dns_servers
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "server": server.dict()
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error creating DHCP server: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dhcp/list")
async def list_dhcp_servers() -> DHCPServerListResponse:
    """List all DHCP servers"""
    try:
        servers = virtual_infra_manager.list_dhcp_servers()
        return DHCPServerListResponse(
            success=True,
            servers=servers,
            count=len(servers)
        )
    except Exception as e:
        logger.error(f"Error listing DHCP servers: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dhcp/{server_id}/leases")
async def get_dhcp_leases(server_id: str) -> DHCPLeasesResponse:
    """Get DHCP leases for a server"""
    try:
        success, leases, message = virtual_infra_manager.get_dhcp_leases(server_id)
        
        if success:
            return DHCPLeasesResponse(
                success=True,
                server_id=server_id,
                leases=leases,
                count=len(leases)
            )
        else:
            raise HTTPException(status_code=404, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting DHCP leases: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ===== Device Management Endpoints =====

@router.post("/devices/create")
async def create_device(request: CreateDeviceRequest):
    """Create a new virtual device"""
    try:
        success, device, message = virtual_infra_manager.create_device(
            name=request.name,
            device_type=request.device_type,
            network_configs=request.network_configs
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "device": device.dict()
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error creating device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/devices/list")
async def list_devices() -> DeviceListResponse:
    """List all virtual devices"""
    try:
        devices = virtual_infra_manager.list_devices()
        return DeviceListResponse(
            success=True,
            devices=devices,
            count=len(devices)
        )
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Get a specific device"""
    try:
        device = virtual_infra_manager.get_device(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return {
            "success": True,
            "device": device.dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/devices/{device_id}/assign-ip")
async def assign_manual_ip(device_id: str, request: ManualIPAssignmentRequest):
    """Manually assign IP to device interface"""
    try:
        success, message = virtual_infra_manager.assign_manual_ip(
            device_id=device_id,
            interface_name=request.interface_name,
            ip_address=request.ip_address,
            network_id=request.network_id
        )
        
        if success:
            device = virtual_infra_manager.get_device(device_id)
            return {
                "success": True,
                "message": message,
                "device": device.dict()
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning IP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/devices/{device_id}")
async def delete_device(device_id: str):
    """Delete a device"""
    try:
        success, message = virtual_infra_manager.delete_device(device_id)
        
        if success:
            return {
                "success": True,
                "message": message
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ===== Traffic Generation Endpoints =====

@router.post("/traffic/start")
async def start_traffic(device_id: str, request: StartTrafficRequest):
    """Start traffic generation from a device"""
    try:
        success, pattern_ids, message = virtual_infra_manager.start_traffic_patterns(
            device_id=device_id,
            patterns=request.traffic_patterns
        )
        
        if success:
            return TrafficPatternResponse(
                success=True,
                message=message,
                device_id=device_id
            )
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error starting traffic: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/traffic/{pattern_id}/stop")
async def stop_traffic(pattern_id: str):
    """Stop a traffic pattern"""
    try:
        success, message = virtual_infra_manager.stop_traffic_pattern(pattern_id)
        
        if success:
            return TrafficPatternResponse(
                success=True,
                message=message,
                pattern_id=pattern_id
            )
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except Exception as e:
        logger.error(f"Error stopping traffic: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/traffic/{pattern_id}/stats")
async def get_traffic_stats(pattern_id: str):
    """Get statistics for a traffic pattern"""
    try:
        success, pattern, message = virtual_infra_manager.get_traffic_stats(pattern_id)
        
        if success:
            return {
                "success": True,
                "pattern": pattern.dict(),
                "message": message
            }
        else:
            raise HTTPException(status_code=404, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting traffic stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ===== Device Types Endpoint =====

@router.get("/device-types")
async def get_device_types():
    """Get available device types"""
    return {
        "success": True,
        "device_types": [device_type.value for device_type in DeviceType]
    }

# ===== Traffic Types Endpoint =====

@router.get("/traffic-types")
async def get_traffic_types():
    """Get available traffic types"""
    return {
        "success": True,
        "traffic_types": [
            {
                "type": "http",
                "description": "HTTP web traffic",
                "default_port": 80
            },
            {
                "type": "dns",
                "description": "DNS queries",
                "default_port": 53
            },
            {
                "type": "ssh",
                "description": "SSH remote access",
                "default_port": 22
            },
            {
                "type": "ftp",
                "description": "File transfer",
                "default_port": 21
            },
            {
                "type": "icmp",
                "description": "ICMP ping",
                "default_port": None
            },
            {
                "type": "custom",
                "description": "Custom traffic",
                "default_port": None
            }
        ]
    }
