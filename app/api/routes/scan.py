"""
Scan API Routes
Network scanning and host discovery
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from app.models import ScanResponse, HostInfo
from app.services.docker_executor import docker_executor
from datetime import datetime
import logging
import json
import os
from typing import Optional

router = APIRouter()
logger = logging.getLogger(__name__)

# Scan data directory (mounted in container)
SCAN_DATA_DIR = "/data"


def get_scan_files() -> list[str]:
    """Get list of scan result files, sorted by newest first"""
    try:
        if not os.path.exists(SCAN_DATA_DIR):
            return []
        
        files = [f for f in os.listdir(SCAN_DATA_DIR) if f.startswith('scan_') and f.endswith('.json')]
        files.sort(reverse=True)  # Newest first
        return files
    except Exception as e:
        logger.error(f"Error listing scan files: {e}")
        return []


def load_scan_file(filename: str) -> Optional[dict]:
    """Load and parse a scan result file"""
    try:
        filepath = os.path.join(SCAN_DATA_DIR, filename)
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return data
    except Exception as e:
        logger.error(f"Error loading scan file {filename}: {e}")
        return None


def parse_scan_data(scan_data: dict) -> ScanResponse:
    """Parse scan data from JSON into ScanResponse model"""
    
    hosts = []
    for host_data in scan_data.get('hosts', []):
        # Parse open ports
        open_ports = []
        for port_info in host_data.get('open_ports', []):
            if isinstance(port_info, dict):
                open_ports.append(f"{port_info.get('port', 0)}/{port_info.get('protocol', 'tcp')}")
            else:
                open_ports.append(str(port_info))
        
        # Create HostInfo object - match field names from models.py
        host = HostInfo(
            ip=host_data.get('ip', 'unknown'),
            mac=host_data.get('mac', ''),
            hostname=host_data.get('hostname', ''),
            vendor=host_data.get('vendor', ''),
            os=host_data.get('os', ''),
            open_ports=open_ports,
            discovered_at=host_data.get('timestamp', datetime.now().isoformat()),
            method=host_data.get('method', 'scan')
        )
        hosts.append(host)
    
    # Create summary
    summary = {
        "total_hosts": len(hosts),
        "hosts_up": len(hosts),
        "total_ports": sum(len(h.open_ports) for h in hosts),
        "scan_duration": scan_data.get('duration', 0.0)
    }
    
    # Get timestamps
    timestamp = scan_data.get('timestamp', datetime.now().isoformat())
    
    return ScanResponse(
        success=True,
        scan_id=scan_data.get('scan_id', 'unknown'),
        start_time=timestamp,
        end_time=timestamp,
        networks=scan_data.get('networks', []),
        hosts=hosts,
        summary=summary,
        status="completed"
    )


@router.get("/latest", response_model=ScanResponse)
async def get_latest_scan():
    """
    Get the most recent scan results
    
    Returns the latest network scan data from the scanner's data directory.
    """
    try:
        logger.info("Fetching latest scan results")
        
        # Get list of scan files
        scan_files = get_scan_files()
        
        if not scan_files:
            # No scan files found - return empty result
            logger.warning("No scan files found")
            return ScanResponse(
                success=True,
                scan_id="none",
                start_time=datetime.now().isoformat(),
                end_time=datetime.now().isoformat(),
                networks=[],
                hosts=[],
                summary={
                    "total_hosts": 0,
                    "hosts_up": 0,
                    "total_ports": 0,
                    "scan_duration": 0.0,
                    "message": "No scans available yet"
                },
                status="pending"
            )
        
        # Load the most recent scan
        latest_file = scan_files[0]
        scan_data = load_scan_file(latest_file)
        
        if not scan_data:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to load scan file: {latest_file}"
            )
        
        # Parse and return
        result = parse_scan_data(scan_data)
        logger.info(f"Retrieved latest scan: {result.scan_id} with {len(result.hosts)} hosts")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting latest scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get latest scan: {str(e)}"
        )


@router.get("/history")
async def get_scan_history(limit: int = 10):
    """
    Get scan history
    
    Returns a list of recent scans with summary information.
    
    Args:
        limit: Maximum number of scans to return (default 10, max 50)
    """
    try:
        limit = min(limit, 50)  # Cap at 50
        
        logger.info(f"Fetching scan history (limit: {limit})")
        
        # Get list of scan files
        scan_files = get_scan_files()[:limit]
        
        if not scan_files:
            return {
                "success": True,
                "scans": [],
                "count": 0,
                "message": "No scans available"
            }
        
        # Load summary info from each scan
        scans = []
        for filename in scan_files:
            scan_data = load_scan_file(filename)
            if scan_data:
                scans.append({
                    "scan_id": scan_data.get('scan_id', filename),
                    "timestamp": scan_data.get('timestamp'),
                    "total_hosts": len(scan_data.get('hosts', [])),
                    "networks": scan_data.get('networks', []),
                    "duration": scan_data.get('duration', 0.0)
                })
        
        logger.info(f"Retrieved {len(scans)} scan history entries")
        
        return {
            "success": True,
            "scans": scans,
            "count": len(scans),
            "message": f"Retrieved {len(scans)} scan(s)"
        }
        
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get scan history: {str(e)}"
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(scan_id: str):
    """
    Get a specific scan by ID
    
    Args:
        scan_id: The scan ID or filename
    """
    try:
        logger.info(f"Fetching scan: {scan_id}")
        
        # Try to find the scan file
        scan_files = get_scan_files()
        
        # Look for exact match or scan ID match
        target_file = None
        for filename in scan_files:
            if filename == scan_id or filename == f"{scan_id}.json":
                target_file = filename
                break
            # Also check if scan_id is in the filename
            if scan_id in filename:
                target_file = filename
                break
        
        if not target_file:
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found: {scan_id}"
            )
        
        # Load scan data
        scan_data = load_scan_file(target_file)
        
        if not scan_data:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to load scan: {scan_id}"
            )
        
        # Parse and return
        result = parse_scan_data(scan_data)
        logger.info(f"Retrieved scan {scan_id} with {len(result.hosts)} hosts")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get scan: {str(e)}"
        )


@router.post("/start")
async def start_scan(background_tasks: BackgroundTasks):
    """
    Trigger a new network scan
    
    Starts a new scan in the background. The scanner container
    runs scans automatically every 5 minutes, but this endpoint
    can trigger an immediate scan.
    
    Note: This is a simplified version that signals the scanner.
    In production, you'd implement proper job queuing.
    """
    try:
        logger.info("Triggering new network scan")
        
        # Check if scanner container is running
        scanner_status = docker_executor.get_container_status("noc_scanner")
        
        if "error" in scanner_status:
            raise HTTPException(
                status_code=500,
                detail=f"Scanner not available: {scanner_status['error']}"
            )
        
        if scanner_status["status"] != "running":
            raise HTTPException(
                status_code=500,
                detail=f"Scanner is not running: {scanner_status['status']}"
            )
        
        # The scanner runs automatically, but we can restart it to trigger immediate scan
        # Or we could implement a signal file that the scanner watches
        # For now, just return success and let the automatic scan continue
        
        return {
            "success": True,
            "message": "Scan request received. Scanner will perform scan on next cycle.",
            "scanner_status": scanner_status["status"],
            "note": "Scanner automatically scans every 5 minutes. Check /api/scan/latest for results."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/status")
async def get_scanner_status():
    """
    Get scanner status and information
    
    Returns information about the scanner container and recent scan activity.
    """
    try:
        # Get scanner container status
        scanner_status = docker_executor.get_container_status("noc_scanner")
        
        if "error" in scanner_status:
            return {
                "success": False,
                "status": "unavailable",
                "message": scanner_status["error"]
            }
        
        # Get latest scan info
        scan_files = get_scan_files()
        latest_scan = None
        if scan_files:
            latest_data = load_scan_file(scan_files[0])
            if latest_data:
                latest_scan = {
                    "scan_id": latest_data.get('scan_id'),
                    "timestamp": latest_data.get('timestamp'),
                    "total_hosts": len(latest_data.get('hosts', []))
                }
        
        return {
            "success": True,
            "scanner_running": scanner_status["status"] == "running",
            "container_status": scanner_status["status"],
            "scan_count": len(scan_files),
            "latest_scan": latest_scan,
            "scan_interval": "300 seconds (5 minutes)",
            "networks_monitored": ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
        }
        
    except Exception as e:
        logger.error(f"Error getting scanner status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get scanner status: {str(e)}"
        )


@router.post("/scan/start-troubleshooting")
async def start_troubleshooting_scenario(issue_type: str):
    """Initiate a troubleshooting game scenario"""
    valid_issues = ['bgp-down', 'radius-failure', 'dns-timeout', 'packet-loss']
    if issue_type not in valid_issues:
        return {"success": False, "error": "Invalid issue type"}
    return {
        "success": True,
        "issue": issue_type,
        "message": f"Scenario started: {issue_type}"
    }