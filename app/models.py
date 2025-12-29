"""
Pydantic models for request/response validation
"""

from pydantic import BaseModel, Field, validator, ConfigDict
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

# ===== Virtual Infrastructure Models =====

class NetworkInfo(BaseModel):
    """Virtual network information"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    id: str = Field(..., description="Unique network identifier")
    name: str = Field(..., description="Network name")
    subnet: str = Field(..., description="Network subnet in CIDR notation (e.g., 10.0.1.0/24)")
    gateway: str = Field(..., description="Gateway IP address")
    dns_servers: List[str] = Field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    created_at: datetime = Field(default_factory=datetime.now)
    status: str = Field(default="active")  # 'active', 'inactive'

class DHCPServerConfig(BaseModel):
    """DHCP server configuration"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    id: str = Field(..., description="Unique DHCP server identifier")
    network_id: str = Field(..., description="Associated network ID")
    subnet: str = Field(..., description="DHCP subnet")
    range_start: str = Field(..., description="DHCP pool start IP")
    range_end: str = Field(..., description="DHCP pool end IP")
    lease_time: int = Field(default=3600, ge=60, le=604800, description="Lease time in seconds")
    gateway: str = Field(..., description="Gateway IP for this DHCP server")
    dns_servers: List[str] = Field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    created_at: datetime = Field(default_factory=datetime.now)
    status: str = Field(default="running")  # 'running', 'stopped'

class DHCPLease(BaseModel):
    """DHCP lease information"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    ip_address: str
    mac_address: str
    hostname: Optional[str]
    lease_time: int
    expires_at: datetime
    status: str  # 'active', 'expired'

class DeviceType(str, Enum):
    """Virtual device types"""
    PHONE = "phone"
    PRINTER = "printer"
    COMPUTER = "computer"

class DeviceInterface(BaseModel):
    """Virtual device network interface"""
    name: str = Field(..., description="Interface name (eth0, eth1, etc.)")
    network_id: str = Field(..., description="Connected network ID")
    mac_address: str = Field(..., description="MAC address")
    ip_address: Optional[str] = Field(None, description="IPv4 address")
    ipv6_address: Optional[str] = Field(None, description="IPv6 address")
    dhcp_enabled: bool = Field(default=False, description="Use DHCP for this interface")
    status: str = Field(default="up")  # 'up', 'down'

class TrafficPattern(BaseModel):
    """Network traffic generation pattern"""
    pattern_type: str = Field(..., description="Type of traffic: 'http', 'dns', 'ssh', 'ftp', 'icmp', 'custom'")
    destination: str = Field(..., description="Destination IP or hostname")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Destination port")
    frequency: int = Field(default=5, ge=1, description="Frequency in seconds between packets")
    duration: Optional[int] = Field(None, ge=1, description="Duration in seconds (None = infinite)")
    packet_size: int = Field(default=64, ge=32, le=65535, description="Packet size in bytes")
    protocol: Optional[str] = Field(None, description="Protocol details or custom payload")

class VirtualDevice(BaseModel):
    """Virtual network device configuration"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    id: str = Field(..., description="Unique device identifier")
    name: str = Field(..., description="Device name")
    device_type: DeviceType = Field(..., description="Type of device")
    interfaces: List[DeviceInterface] = Field(default_factory=list, description="Network interfaces")
    status: str = Field(default="stopped")  # 'running', 'stopped', 'error'
    active_traffic_patterns: List[str] = Field(default_factory=list, description="IDs of active traffic patterns")
    created_at: datetime = Field(default_factory=datetime.now)
    last_packet_sent: Optional[datetime] = Field(None)

class TrafficPatternInstance(BaseModel):
    """Instance of a traffic pattern being generated"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    id: str = Field(..., description="Pattern instance ID")
    device_id: str = Field(..., description="Device ID generating traffic")
    pattern: TrafficPattern = Field(..., description="Traffic pattern configuration")
    status: str = Field(default="active")  # 'active', 'paused', 'stopped'
    packets_sent: int = Field(default=0)
    bytes_sent: int = Field(default=0)
    started_at: datetime = Field(default_factory=datetime.now)
    last_sent_at: Optional[datetime] = Field(None)

# ===== Request Models for Virtual Infrastructure =====

class CreateNetworkRequest(BaseModel):
    """Request to create a new virtual network"""
    name: str = Field(..., min_length=1, max_length=64)
    subnet: str = Field(..., description="CIDR notation (e.g., 10.0.1.0/24)")
    gateway: str
    dns_servers: List[str] = Field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])

class CreateDHCPServerRequest(BaseModel):
    """Request to create a DHCP server"""
    network_id: str
    range_start: str
    range_end: str
    lease_time: int = Field(default=3600, ge=60, le=604800)
    gateway: str
    dns_servers: List[str] = Field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])

class CreateDeviceRequest(BaseModel):
    """Request to create a virtual device"""
    name: str = Field(..., min_length=1, max_length=64)
    device_type: DeviceType
    network_configs: List[Dict[str, Any]] = Field(
        ...,
        description="List of network interface configs with network_id, dhcp_enabled, and optional ip_address"
    )

class StartTrafficRequest(BaseModel):
    """Request to start traffic generation"""
    device_id: str
    traffic_patterns: List[TrafficPattern] = Field(..., min_items=1)

class ManualIPAssignmentRequest(BaseModel):
    """Request to manually assign IP to device interface"""
    device_id: str
    interface_name: str
    ip_address: str
    network_id: str = Field(..., description="Must match the network the interface is connected to")

# ===== Response Models for Virtual Infrastructure =====

class NetworkListResponse(BaseModel):
    """Response containing list of networks"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    success: bool
    networks: List[NetworkInfo]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class DHCPServerListResponse(BaseModel):
    """Response containing DHCP servers"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    success: bool
    servers: List[DHCPServerConfig]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class DHCPLeasesResponse(BaseModel):
    """Response containing DHCP leases"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    success: bool
    server_id: str
    leases: List[DHCPLease]
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class DeviceListResponse(BaseModel):
    """Response containing list of devices"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    success: bool
    devices: List['VirtualDevice']
    count: int
    timestamp: datetime = Field(default_factory=datetime.now)

class TrafficPatternResponse(BaseModel):
    """Response for traffic pattern operations"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    success: bool
    message: str
    pattern_id: Optional[str] = None
    device_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)

# ===== Error Response =====

class ErrorResponse(BaseModel):
    """Standard error response"""
    success: bool = False
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)