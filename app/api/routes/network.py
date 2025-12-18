"""
Network API Routes
Routing tables, OSPF neighbors, BGP peers
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from app.config import settings
from pathlib import Path
from app.models import RoutingTableResponse, Route, OSPFNeighborsResponse, OSPFNeighbor, BGPSummaryResponse, BGPPeer
from app.services.docker_executor import docker_executor
from app.services.pcap_analyzer import PCAPAnalyzer
from datetime import datetime
import logging
import re

DATA_DIR = Path(settings.DATA_DIR)
router = APIRouter()
logger = logging.getLogger(__name__)

# --- Packet Capture & Analysis Endpoints ---

@router.post("/capture/start")
async def start_packet_capture(
    interface: str = "eth0",
    duration: int = 10,
    filter_expr: str = ""
):
    """Start packet capture on scanner container
    
    Args:
        interface: Network interface to capture on
        duration: Duration in seconds
        filter_expr: Optional BPF filter expression
    """
    try:
        logger.info(f"Starting packet capture on {interface} for {duration}s")
        
        # Use tcpdump to capture packets
        pcap_filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        output_file = DATA_DIR / pcap_filename
        
        # Build tcpdump command
        cmd = ["tcpdump", "-i", interface, "-w", str(output_file), "-G", str(duration)]
        if filter_expr:
            cmd.append(filter_expr)
        
        success, output = docker_executor.exec_network_command(cmd, timeout=duration + 5)
        
        if success or output_file.exists():
            logger.info(f"Packet capture completed: {pcap_filename}")
            return {
                "success": True,
                "message": f"Captured packets on {interface} for {duration}s",
                "filename": pcap_filename,
                "file_size": output_file.stat().st_size if output_file.exists() else 0
            }
        else:
            logger.warning(f"Packet capture may have failed: {output}")
            return {
                "success": False,
                "message": "Packet capture failed or no traffic captured",
                "error": output
            }
    
    except Exception as e:
        logger.error(f"Error starting packet capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/capture/list")
async def list_captures():
    """List all captured PCAP files"""
    try:
        if not DATA_DIR.exists():
            return {"success": True, "captures": []}
        
        captures = [f.name for f in DATA_DIR.glob('*.pcap*')]
        logger.info(f"Found {len(captures)} PCAP files")
        return {"success": True, "captures": sorted(captures, reverse=True)}
    except Exception as e:
        logger.error(f"Error listing captures: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/capture/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload a PCAP file for analysis
    
    Args:
        file: PCAP file to upload
        
    Returns:
        Filename and status
    """
    try:
        # Ensure DATA_DIR exists
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        # Generate filename from upload
        filename = f"uploaded_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = DATA_DIR / filename
        
        # Save file
        contents = await file.read()
        with open(filepath, 'wb') as f:
            f.write(contents)
        
        logger.info(f"PCAP file uploaded: {filename} ({len(contents)} bytes)")
        
        return {
            "success": True,
            "filename": filename,
            "size": len(contents),
            "message": f"File uploaded successfully: {filename}"
        }
    
    except Exception as e:
        logger.error(f"Error uploading PCAP file: {e}")
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

@router.post("/capture/analyze")
async def analyze_pcap(filename: str):
    """Analyze a PCAP file
    
    Args:
        filename: Name of PCAP file in DATA_DIR
        
    Returns:
        Analysis results including summary, protocols, conversations, etc.
    """
    pcap_path = DATA_DIR / filename
    
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {pcap_path}")
        raise HTTPException(
            status_code=404,
            detail=f"PCAP file not found: {filename}"
        )
    
    try:
        logger.info(f"Analyzing PCAP file: {filename}")
        
        # Use the real PCAP analyzer
        analyzer = PCAPAnalyzer(pcap_path)
        analysis_result = analyzer.export_json()
        
        logger.info(f"Successfully analyzed {filename}: {analysis_result['summary']['total_packets']} packets")
        
        return {
            "success": True,
            "filename": filename,
            "analysis": analysis_result
        }
    
    except FileNotFoundError as e:
        logger.error(f"PCAP file not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        logger.error(f"Scapy not available: {e}")
        raise HTTPException(
            status_code=500,
            detail="PCAP analysis tools not available (Scapy not installed)"
        )
    except Exception as e:
        logger.error(f"Error analyzing PCAP file: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing PCAP file: {str(e)}"
        )

@router.get("/capture/download/{filename}")
async def download_capture(filename: str):
    """Download a PCAP file"""
    pcap_path = DATA_DIR / filename
    if not pcap_path.exists():
        return {"success": False, "error": "File not found"}
    return FileResponse(
        pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=filename
    )


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
    
    logger.debug(f"Parsing BGP summary output:\n{output}")
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Skip empty lines and headers
        if not line or 'Neighbor' in line or 'V' in line or '---' in line:
            continue
        
        # More flexible regex that handles varying whitespace
        # Format: IP_ADDRESS V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        peer_match = re.match(
            r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+([\d:hms]+)\s+(.+)$',
            line
        )
        
        if peer_match:
            neighbor = peer_match.group(1)
            remote_as = int(peer_match.group(2))
            msg_rcvd = int(peer_match.group(3))
            msg_sent = int(peer_match.group(4))
            uptime = peer_match.group(5)
            state_pfx = peer_match.group(6).strip()
            
            # Determine state and prefix count
            if state_pfx.isdigit():
                state = "Established"
                prefixes_received = int(state_pfx)
            else:
                state = state_pfx
                prefixes_received = 0
            
            logger.debug(f"Parsed BGP peer: {neighbor} AS{remote_as} State:{state}")
            
            peers.append(BGPPeer(
                peer_ip=neighbor,
                peer_as=remote_as,
                state=state,
                uptime=uptime,
                received_prefixes=prefixes_received,
                sent_prefixes=0
            ))
        else:
            logger.debug(f"BGP line didn't match regex: {line}")
    
    logger.info(f"Parsed {len(peers)} BGP peers from output")
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
            count=len(routes)
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
            count=len(neighbors)
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
        
        logger.debug(f"Docker exec result: success={success}, output length={len(output)}")
        logger.debug(f"Raw output:\n{output}")
        
        if not success:
            logger.error(f"Failed to get BGP summary from {router}: {output}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get BGP summary from {router}: {output}"
            )
        
        # Check if output is empty
        if not output or output.strip() == "":
            logger.warning(f"BGP summary output is empty from {router}")
            return BGPSummaryResponse(
                success=True,
                router=router,
                local_as=65001 if router == 'router1' else 65002,
                peers=[],
                count=0
            )
        
        # Parse BGP peers
        peers = parse_bgp_summary(output)
        
        logger.info(f"Retrieved {len(peers)} BGP peers from {router}")
        
        return BGPSummaryResponse(
            success=True,
            router=router,
            local_as=65001 if router == 'router1' else 65002,  # AS numbers from your config
            peers=peers,
            count=len(peers)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting BGP summary from {router}: {e}", exc_info=True)
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