"""
Diagnostics API Routes
Endpoints for network diagnostic tools
"""

from fastapi import APIRouter, HTTPException
from app.models import (
    PingRequest,
    PingResponse,
    TracerouteRequest,
    TracerouteResponse,
    PortCheckRequest,
    PortCheckResponse,
    DNSLookupRequest,
    DNSLookupResponse,
    ARPTableResponse,
    ARPEntry
)
from app.services.diagnostics import diagnostics_service
from app.services.docker_executor import docker_executor
import logging
import re

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/ping", response_model=PingResponse)
async def ping(request: PingRequest):
    """
    Ping a target host
    
    - **target**: IP address or hostname to ping
    - **count**: Number of ping packets (1-10)
    - **timeout**: Timeout per packet in seconds
    """
    try:
        result = diagnostics_service.ping(
            target=request.target,
            count=request.count,
            timeout=request.timeout
        )
        return result
    except Exception as e:
        logger.error(f"Ping failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/traceroute", response_model=TracerouteResponse)
async def traceroute(request: TracerouteRequest):
    """
    Trace route to a target host
    
    - **target**: IP address or hostname
    - **max_hops**: Maximum number of hops (1-64)
    - **timeout**: Timeout per hop in seconds
    """
    try:
        result = diagnostics_service.traceroute(
            target=request.target,
            max_hops=request.max_hops,
            timeout=request.timeout
        )
        return result
    except Exception as e:
        logger.error(f"Traceroute failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/port-check", response_model=PortCheckResponse)
async def check_port(request: PortCheckRequest):
    """
    Check if a port is open on a host
    
    - **host**: Target host
    - **port**: Port number (1-65535)
    - **protocol**: Protocol (tcp or udp)
    """
    try:
        result = diagnostics_service.check_port(
            host=request.host,
            port=request.port,
            protocol=request.protocol
        )
        return result
            
    except Exception as e:
        logger.error(f"Port check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/dns-lookup", response_model=DNSLookupResponse)
async def dns_lookup(request: DNSLookupRequest):
    """
    Perform DNS lookup for a hostname
    
    - **hostname**: Hostname to resolve
    - **record_type**: DNS record type (A, AAAA, MX, NS, TXT, CNAME)
    """
    try:
        result = diagnostics_service.dns_lookup(
            hostname=request.hostname,
            record_type=request.record_type
        )
        return result
            
    except Exception as e:
        logger.error(f"DNS lookup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/arp-table", response_model=ARPTableResponse)
async def get_arp_table():
    """
    Get ARP table from scanner container
    
    Shows IP to MAC address mappings
    """
    try:
        # Execute 'ip neigh show' command
        success, output = docker_executor.exec_network_command(["ip", "neigh", "show"])
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to retrieve ARP table")
        
        # Parse ARP table
        entries = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            # Parse line like: "10.0.1.1 dev eth0 lladdr 02:42:0a:00:01:01 REACHABLE"
            parts = line.split()
            if len(parts) >= 5:
                entry = ARPEntry(
                    ip_address=parts[0],
                    mac_address=parts[4] if 'lladdr' in line else "incomplete",
                    interface=parts[2],
                    type="dynamic"
                )
                entries.append(entry)
        
        return ARPTableResponse(
            success=True,
            entries=entries,
            count=len(entries)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get ARP table: {e}")
        raise HTTPException(status_code=500, detail=str(e))