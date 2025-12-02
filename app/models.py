"""
Pydantic models for request/response validation
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# ===== Request Models =====

class PingRequest(BaseModel):
    """Ping diagnostic request"""
    target: str = Field(..., description="Target IP address or hostname")
    count: int = Field(default=3, ge=1, le=10, description="Number of ping packets")
    timeout: int = Field(default=5, ge=1, le=30, description="Timeout in seconds")
    
    @validator('target')
    def validate_target(cls, v):
        """Basic validation for target"""
        if not v or len(v) < 3:
            raise ValueError('Invalid target')
        return v

class TracerouteRequest(BaseModel):
    """Traceroute diagnostic request"""
    target: str = Field(..., description="Target IP address or hostname")
    max_hops: int = Field(default=30, ge=1, le=64, description="Maximum number of hops")
    timeout: int = Field(default=5, ge=1, le=30, description="Timeout per hop")

class PortCheckRequest(BaseModel):
    """Port connectivity check request"""
    host: str = Field(..., description="Target host")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")

class DNSLookupRequest(BaseModel):
    """DNS lookup request"""
    hostname: str = Field(..., description="Hostname to resolve")
    record_type: str = Field(default="A", pattern="^(A|AAAA|MX|NS|TXT|CNAME)$")

class RADIUSTestRequest(BaseModel):
    """RADIUS authentication test request"""
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=64)
    server: Optional[str] = Field(default=None, description="Override default RADIUS server")

class ScanRequest(BaseModel):
    """Network scan request"""
    networks: Optional[List[str]] = Field(default=None, description="Networks to scan")
    port_range: Optional[str] = Field(default=None, description="Port range (e.g., '1-1024')")
    scan_type: str = Field(default="quick", pattern="^(quick|full|ports_only)$")

# ===== Response Models =====

class StatusResponse(BaseModel):
    """Generic status response"""
    success: bool
    message: str
    timestamp: datetime = Field(default_factory=datetime.now)

class PingResponse(BaseModel):
    """Ping diagnostic response"""
    success: bool
    target: str
    packets_sent: int
    packets_received: int
    packet_loss_pct: float
    min_rtt: Optional[float] = None
    avg_rtt: Optional[float] = None
    max_rtt: Optional[float] = None
    output: str
    timestamp: datetime = Field(default_factory=datetime.now)

class TracerouteHop(BaseModel):
    """Single hop in traceroute"""
    hop_number: int
    ip_address: Optional[str]
    hostname: Optional[str]
    rtt: Optional[float]  # milliseconds

class TracerouteResponse(BaseModel):
    """Traceroute diagnostic response"""
    success: bool
    target: str
    hops: List[TracerouteHop]
    output: str
    timestamp: datetime = Field(default_factory=datetime.now)

class PortCheckResponse(BaseModel):
    """Port check response"""
    success: bool
    host: str
    port: int
    protocol: str
    status: str  # 'open', 'closed', 'filtered'
    service: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)

class ARPEntry(BaseModel):
    """ARP table entry"""
    ip_address: str
    mac_address: str
    interface: Optional[str] = None
    type: str  # 'static' or 'dynamic'

class ARPTableResponse(BaseModel):
    """ARP table response"""
    success: bool
    entries: List[ARPEntry]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class Route(BaseModel):
    """Routing table entry"""
    network: str
    gateway: Optional[str]
    interface: str
    metric: Optional[int]
    protocol: Optional[str]  # 'C' (connected), 'O' (OSPF), 'B' (BGP), etc.

class RoutingTableResponse(BaseModel):
    """Routing table response"""
    success: bool
    router: str
    routes: List[Route]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class OSPFNeighbor(BaseModel):
    """OSPF neighbor information"""
    neighbor_id: str
    priority: int
    state: str  # 'Full', '2-Way', etc.
    dead_time: str
    address: str
    interface: str

class OSPFNeighborsResponse(BaseModel):
    """OSPF neighbors response"""
    success: bool
    router: str
    neighbors: List[OSPFNeighbor]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class BGPPeer(BaseModel):
    """BGP peer information"""
    peer_ip: str
    peer_as: int
    state: str  # 'Established', 'Active', 'Idle', etc.
    uptime: Optional[str]
    received_prefixes: Optional[int]
    sent_prefixes: Optional[int]

class BGPSummaryResponse(BaseModel):
    """BGP summary response"""
    success: bool
    router: str
    local_as: Optional[int]
    peers: List[BGPPeer]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class HostInfo(BaseModel):
    """Discovered host information"""
    ip: str
    mac: Optional[str]
    hostname: Optional[str]
    open_ports: List[int] = []
    services: List[Dict[str, Any]] = []
    discovered_at: datetime
    method: str  # 'ARP', 'ICMP', etc.

class ScanResponse(BaseModel):
    """Network scan response"""
    success: bool
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime]
    networks: List[str]
    hosts: List[HostInfo]
    summary: Dict[str, int]
    status: str  # 'running', 'completed', 'failed'

class RADIUSTestResponse(BaseModel):
    """RADIUS test response"""
    success: bool
    username: str
    server: str
    authenticated: bool
    message: str
    response_time: Optional[float] = None  # milliseconds
    timestamp: datetime = Field(default_factory=datetime.now)

class ContainerStatus(BaseModel):
    """Docker container status"""
    name: str
    status: str  # 'running', 'exited', etc.
    health: Optional[str]  # 'healthy', 'unhealthy', 'starting'
    uptime: Optional[str]

class HealthCheckResponse(BaseModel):
    """System health check response"""
    success: bool
    status: str  # 'healthy', 'degraded', 'unhealthy'
    containers: List[ContainerStatus]
    checks: Dict[str, bool]  # Various health checks
    timestamp: datetime = Field(default_factory=datetime.now)

class LayerHealth(BaseModel):
    """OSI layer health status"""
    layer: int
    name: str
    status: str  # 'healthy', 'warning', 'critical'
    issues: List[str] = []

class LayerHealthResponse(BaseModel):
    """Layer-by-layer health response"""
    success: bool
    layers: List[LayerHealth]
    overall_status: str
    timestamp: datetime = Field(default_factory=datetime.now)

class DNSLookupResponse(BaseModel):
    """DNS lookup response"""
    success: bool
    hostname: str
    record_type: str
    answers: List[str]
    query_time: float  # milliseconds
    nameserver: Optional[str]
    timestamp: datetime = Field(default_factory=datetime.now)

# ===== Error Response =====

class ErrorResponse(BaseModel):
    """Standard error response"""
    success: bool = False
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)