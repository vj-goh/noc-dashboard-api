"""
Network API Routes
Routing tables, OSPF neighbors, BGP peers
"""

from fastapi import APIRouter, HTTPException
from app.models import RoutingTableResponse, Route, OSPFNeighborsResponse, OSPFNeighbor, BGPSummaryResponse, BGPPeer
from app.services.docker_executor import docker_executor
from datetime import datetime
import logging
import re

router = APIRouter()
logger = logging.getLogger(__name__)


def parse_routing_table(output: str) -> list[Route]:
    """Parse 'show ip route' output into Route objects"""
    routes = []
    
    # Parse FRRouting output
    # Example: "C>* 10.0.1.0/24 is directly connected, eth0"
    # Example: "O>* 10.0.3.0/24 [110/20] via 10.0.2.2, eth1"
    
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('Codes:') or line.startswith('Gateway'):
            continue
        
        # Match route lines
        # Pattern: [Protocol][Flags] Network [metric] via Gateway, Interface
        route_match = re.match(
            r'([A-Z])([>*\s]+)\s*(\d+\.\d+\.\d+\.\d+/\d+)(?:\s+\[(\d+)/(\d+)\])?\s+(?:via\s+(\d+\.\d+\.\d+\.\d+))?,?\s*(\w+)?',
            line
        )
        
        if route_match:
            protocol_code = route_match.group(1)
            network = route_match.group(3)
            metric = route_match.group(5) if route_match.group(5) else "0"
            next_hop = route_match.group(6) if route_match.group(6) else "directly connected"
            interface = route_match.group(7) if route_match.group(7) else "unknown"
            
            # Map protocol codes
            protocol_map = {
                'C': 'connected',
                'S': 'static',
                'O': 'OSPF',
                'B': 'BGP',
                'K': 'kernel',
                'R': 'RIP'
            }
            protocol = protocol_map.get(protocol_code, 'unknown')
            
            routes.append(Route(
                network=network,
                gateway=next_hop,
                interface=interface,
                protocol=protocol,
                metric=int(metric)
            ))
    
    return routes


def parse_ospf_neighbors(output: str) -> list[OSPFNeighbor]:
    """Parse 'show ip ospf neighbor' output into OSPFNeighbor objects"""
    neighbors = []
    
    # Example output:
    # Neighbor ID     Pri State           Dead Time Address         Interface
    # 2.2.2.2           1 Full/DR           37.123s 10.0.2.2        eth1:10.0.2.1
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Match neighbor lines (skip header)
        neighbor_match = re.match(
            r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+([\w/]+)\s+([\d.]+)s\s+(\d+\.\d+\.\d+\.\d+)\s+([\w:.\d]+)',
            line
        )
        
        if neighbor_match:
            neighbor_id = neighbor_match.group(1)
            priority = int(neighbor_match.group(2))
            state = neighbor_match.group(3)
            dead_time = neighbor_match.group(4)
            address = neighbor_match.group(5)
            interface = neighbor_match.group(6).split(':')[0]  # Remove IP suffix if present
            
            neighbors.append(OSPFNeighbor(
                neighbor_id=neighbor_id,
                priority=priority,
                state=state,
                dead_time=dead_time,
                address=address,
                interface=interface
            ))
    
    return neighbors


def parse_bgp_summary(output: str) -> list[BGPPeer]:
    """Parse 'show ip bgp summary' output into BGPPeer objects"""
    peers = []
    
    # Example output:
    # Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd
    # 10.0.2.2        4      65002      45      46        0    0    0 00:20:15            1
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Match peer lines
        peer_match = re.match(
            r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+([\d:]+)\s+(\w+|\d+)',
            line
        )
        
        if peer_match:
            neighbor = peer_match.group(1)
            remote_as = int(peer_match.group(3))
            msg_rcvd = int(peer_match.group(4))
            msg_sent = int(peer_match.group(5))
            uptime = peer_match.group(6)
            state_pfx = peer_match.group(7)
            
            # Determine state and prefix count
            if state_pfx.isdigit():
                state = "Established"
                prefixes_received = int(state_pfx)
            else:
                state = state_pfx
                prefixes_received = 0
            
            peers.append(BGPPeer(
                neighbor=neighbor,
                remote_as=remote_as,
                state=state,
                uptime=uptime,
                prefixes_received=prefixes_received,
                msg_rcvd=msg_rcvd,
                msg_sent=msg_sent
            ))
    
    return peers


@router.get("/routing-table/{router}", response_model=RoutingTableResponse)
async def get_routing_table(router: str):
    """
    Get routing table from a router
    
    Executes 'show ip route' via vtysh and parses the output.
    
    Args:
        router: Router name ('router1' or 'router2')
    """
    if router not in ['router1', 'router2']:
        raise HTTPException(status_code=400, detail="Router must be 'router1' or 'router2'")
    
    try:
        logger.info(f"Fetching routing table from {router}")
        
        # Execute vtysh command
        success, output = docker_executor.exec_vtysh_command(
            router=router,
            command="show ip route"
        )
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get routing table from {router}: {output}"
            )
        
        # Parse routes
        routes = parse_routing_table(output)
        
        logger.info(f"Retrieved {len(routes)} routes from {router}")
        
        return RoutingTableResponse(
            success=True,
            router=router,
            routes=routes,
            total=len(routes)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting routing table from {router}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get routing table: {str(e)}"
        )


@router.get("/ospf/neighbors", response_model=OSPFNeighborsResponse)
async def get_ospf_neighbors(router: str = "router1"):
    """
    Get OSPF neighbors from a router
    
    Executes 'show ip ospf neighbor' via vtysh and parses the output.
    
    Args:
        router: Router name ('router1' or 'router2'), defaults to router1
    """
    if router not in ['router1', 'router2']:
        raise HTTPException(status_code=400, detail="Router must be 'router1' or 'router2'")
    
    try:
        logger.info(f"Fetching OSPF neighbors from {router}")
        
        # Execute vtysh command
        success, output = docker_executor.exec_vtysh_command(
            router=router,
            command="show ip ospf neighbor"
        )
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get OSPF neighbors from {router}: {output}"
            )
        
        # Parse neighbors
        neighbors = parse_ospf_neighbors(output)
        
        logger.info(f"Retrieved {len(neighbors)} OSPF neighbors from {router}")
        
        return OSPFNeighborsResponse(
            success=True,
            router=router,
            neighbors=neighbors,
            total=len(neighbors)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting OSPF neighbors from {router}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get OSPF neighbors: {str(e)}"
        )


@router.get("/bgp/summary", response_model=BGPSummaryResponse)
async def get_bgp_summary(router: str = "router1"):
    """
    Get BGP summary from a router
    
    Executes 'show ip bgp summary' via vtysh and parses the output.
    
    Args:
        router: Router name ('router1' or 'router2'), defaults to router1
    """
    if router not in ['router1', 'router2']:
        raise HTTPException(status_code=400, detail="Router must be 'router1' or 'router2'")
    
    try:
        logger.info(f"Fetching BGP summary from {router}")
        
        # Execute vtysh command
        success, output = docker_executor.exec_vtysh_command(
            router=router,
            command="show ip bgp summary"
        )
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get BGP summary from {router}: {output}"
            )
        
        # Parse BGP peers
        peers = parse_bgp_summary(output)
        
        logger.info(f"Retrieved {len(peers)} BGP peers from {router}")
        
        return BGPSummaryResponse(
            success=True,
            router=router,
            peers=peers,
            total=len(peers)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting BGP summary from {router}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get BGP summary: {str(e)}"
        )


@router.get("/interfaces/{router}")
async def get_interfaces(router: str):
    """
    Get interface status from a router
    
    Executes 'show interface brief' via vtysh.
    
    Args:
        router: Router name ('router1' or 'router2')
    """
    if router not in ['router1', 'router2']:
        raise HTTPException(status_code=400, detail="Router must be 'router1' or 'router2'")
    
    try:
        logger.info(f"Fetching interfaces from {router}")
        
        # Execute vtysh command
        success, output = docker_executor.exec_vtysh_command(
            router=router,
            command="show interface brief"
        )
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get interfaces from {router}: {output}"
            )
        
        return {
            "success": True,
            "router": router,
            "output": output,
            "message": "Interface information retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting interfaces from {router}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get interfaces: {str(e)}"
        )