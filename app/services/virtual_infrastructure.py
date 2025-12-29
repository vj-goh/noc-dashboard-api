"""
Virtual Infrastructure Management Service
Manages DHCP servers, virtual devices, and traffic generation
"""

import json
import uuid
import logging
import threading
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from app.models import (
    NetworkInfo, DHCPServerConfig, VirtualDevice, TrafficPattern,
    TrafficPatternInstance, DeviceInterface, DHCPLease, DeviceType
)
from app.config import settings

logger = logging.getLogger(__name__)

class VirtualInfrastructureManager:
    """Manages virtual networks, DHCP servers, devices, and traffic patterns"""
    
    def __init__(self):
        try:
            self.data_dir = Path(settings.DATA_DIR)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Initialized data directory: {self.data_dir}")
        except Exception as e:
            logger.error(f"Failed to create data directory: {e}")
            # Fallback to current directory
            self.data_dir = Path(".")
        
        self.networks_file = self.data_dir / "virtual_networks.json"
        self.dhcp_servers_file = self.data_dir / "dhcp_servers.json"
        self.devices_file = self.data_dir / "virtual_devices.json"
        self.traffic_patterns_file = self.data_dir / "traffic_patterns.json"
        
        # In-memory storage
        self.networks: Dict[str, NetworkInfo] = {}
        self.dhcp_servers: Dict[str, DHCPServerConfig] = {}
        self.devices: Dict[str, VirtualDevice] = {}
        self.traffic_patterns: Dict[str, TrafficPatternInstance] = {}
        
        # Traffic generation threads
        self.traffic_threads: Dict[str, threading.Thread] = {}
        
        # Load existing data
        self._load_data()
    
    # ===== File I/O Methods =====
    
    def _load_data(self):
        """Load all data from disk"""
        try:
            if self.networks_file.exists():
                with open(self.networks_file, 'r') as f:
                    data = json.load(f)
                    for net_id, net_data in data.items():
                        self.networks[net_id] = NetworkInfo(**net_data)
            
            if self.dhcp_servers_file.exists():
                with open(self.dhcp_servers_file, 'r') as f:
                    data = json.load(f)
                    for srv_id, srv_data in data.items():
                        self.dhcp_servers[srv_id] = DHCPServerConfig(**srv_data)
            
            if self.devices_file.exists():
                with open(self.devices_file, 'r') as f:
                    data = json.load(f)
                    for dev_id, dev_data in data.items():
                        self.devices[dev_id] = VirtualDevice(**dev_data)
            
            if self.traffic_patterns_file.exists():
                with open(self.traffic_patterns_file, 'r') as f:
                    data = json.load(f)
                    for pat_id, pat_data in data.items():
                        self.traffic_patterns[pat_id] = TrafficPatternInstance(**pat_data)
            
            logger.info(f"Loaded {len(self.networks)} networks, {len(self.dhcp_servers)} DHCP servers, "
                       f"{len(self.devices)} devices, {len(self.traffic_patterns)} traffic patterns")
        except Exception as e:
            logger.error(f"Error loading data: {e}")
    
    def _save_data(self, data_type: str):
        """Save data to disk"""
        try:
            if data_type == 'networks':
                with open(self.networks_file, 'w') as f:
                    json.dump({k: v.model_dump() for k, v in self.networks.items()}, f, default=str, indent=2)
            elif data_type == 'dhcp_servers':
                with open(self.dhcp_servers_file, 'w') as f:
                    json.dump({k: v.model_dump() for k, v in self.dhcp_servers.items()}, f, default=str, indent=2)
            elif data_type == 'devices':
                with open(self.devices_file, 'w') as f:
                    json.dump({k: v.model_dump() for k, v in self.devices.items()}, f, default=str, indent=2)
            elif data_type == 'traffic_patterns':
                with open(self.traffic_patterns_file, 'w') as f:
                    json.dump({k: v.model_dump() for k, v in self.traffic_patterns.items()}, f, default=str, indent=2)
        except Exception as e:
            logger.error(f"Error saving {data_type}: {e}")
    
    # ===== Network Management =====
    
    def create_network(self, name: str, subnet: str, gateway: str, 
                      dns_servers: Optional[List[str]] = None) -> Tuple[bool, NetworkInfo, str]:
        """Create a new virtual network"""
        try:
            # Validate subnet format
            if not self._validate_subnet(subnet):
                return False, None, "Invalid subnet format. Use CIDR notation (e.g., 10.0.1.0/24)"
            
            # Check for duplicate subnets
            for net in self.networks.values():
                if net.subnet == subnet:
                    return False, None, f"Network with subnet {subnet} already exists"
            
            network_id = f"net_{uuid.uuid4().hex[:8]}"
            dns_servers = dns_servers or ["8.8.8.8", "8.8.4.4"]
            
            network = NetworkInfo(
                id=network_id,
                name=name,
                subnet=subnet,
                gateway=gateway,
                dns_servers=dns_servers
            )
            
            self.networks[network_id] = network
            self._save_data('networks')
            logger.info(f"Created network: {network_id} ({name}) - {subnet}")
            return True, network, "Network created successfully"
        
        except Exception as e:
            logger.error(f"Error creating network: {e}")
            return False, None, str(e)
    
    def list_networks(self) -> List[NetworkInfo]:
        """List all networks including pre-existing ones"""
        networks = list(self.networks.values())
        
        # Add pre-existing networks from system configuration
        existing_subnets = {n.subnet for n in networks}
        
        predefined = [
            {"name": "Core Network", "subnet": "10.0.1.0/24", "gateway": "10.0.1.1", "id": "net_core"},
            {"name": "Edge Network", "subnet": "10.0.2.0/24", "gateway": "10.0.2.1", "id": "net_edge"},
            {"name": "Client Network", "subnet": "10.0.3.0/24", "gateway": "10.0.3.1", "id": "net_client"},
        ]
        
        for net_def in predefined:
            if net_def["subnet"] not in existing_subnets:
                # Add as predefined (not editable/deletable from system)
                predefined_net = NetworkInfo(
                    id=net_def["id"],
                    name=net_def["name"],
                    subnet=net_def["subnet"],
                    gateway=net_def["gateway"],
                    dns_servers=["8.8.8.8", "8.8.4.4"],
                    status="active"
                )
                networks.append(predefined_net)
        
        return networks
    
    def get_network(self, network_id: str) -> Optional[NetworkInfo]:
        """Get network by ID, including predefined networks"""
        # Check user-created networks first
        if network_id in self.networks:
            return self.networks[network_id]
        
        # Check predefined networks
        predefined = {
            "net_core": NetworkInfo(id="net_core", name="Core Network", subnet="10.0.1.0/24", gateway="10.0.1.1", dns_servers=["8.8.8.8", "8.8.4.4"]),
            "net_edge": NetworkInfo(id="net_edge", name="Edge Network", subnet="10.0.2.0/24", gateway="10.0.2.1", dns_servers=["8.8.8.8", "8.8.4.4"]),
            "net_client": NetworkInfo(id="net_client", name="Client Network", subnet="10.0.3.0/24", gateway="10.0.3.1", dns_servers=["8.8.8.8", "8.8.4.4"]),
        }
        
        return predefined.get(network_id)
    
    def delete_network(self, network_id: str) -> Tuple[bool, str]:
        """Delete a network"""
        try:
            # Prevent deletion of predefined networks
            if network_id in ["net_core", "net_edge", "net_client"]:
                return False, "Cannot delete predefined system networks"
            
            # Check if network has DHCP servers
            for srv in self.dhcp_servers.values():
                if srv.network_id == network_id:
                    return False, "Cannot delete network with active DHCP servers"
            
            # Check if network has devices
            for dev in self.devices.values():
                for iface in dev.interfaces:
                    if iface.network_id == network_id:
                        return False, "Cannot delete network with connected devices"
            
            if network_id in self.networks:
                del self.networks[network_id]
                self._save_data('networks')
                logger.info(f"Deleted network: {network_id}")
                return True, "Network deleted successfully"
            return False, "Network not found"
        
        except Exception as e:
            logger.error(f"Error deleting network: {e}")
            return False, str(e)
    
    # ===== DHCP Server Management =====
    
    def create_dhcp_server(self, network_id: str, range_start: str, range_end: str,
                          lease_time: int = 3600, gateway: Optional[str] = None,
                          dns_servers: Optional[List[str]] = None) -> Tuple[bool, DHCPServerConfig, str]:
        """Create a DHCP server for a network"""
        try:
            # Validate network exists (check both user-created and predefined)
            network = self.get_network(network_id)
            if not network:
                return False, None, f"Network {network_id} not found"
            
            # Check if DHCP server already exists for this network
            for srv in self.dhcp_servers.values():
                if srv.network_id == network_id:
                    return False, None, f"DHCP server already exists for network {network_id}"
            
            # Validate IP addresses are in network
            if not self._validate_ip_in_subnet(range_start, network.subnet):
                return False, None, f"Range start {range_start} not in subnet {network.subnet}"
            if not self._validate_ip_in_subnet(range_end, network.subnet):
                return False, None, f"Range end {range_end} not in subnet {network.subnet}"
            
            server_id = f"dhcp_{uuid.uuid4().hex[:8]}"
            gateway = gateway or network.gateway
            dns_servers = dns_servers or network.dns_servers
            
            dhcp_server = DHCPServerConfig(
                id=server_id,
                network_id=network_id,
                subnet=network.subnet,
                range_start=range_start,
                range_end=range_end,
                lease_time=lease_time,
                gateway=gateway,
                dns_servers=dns_servers
            )
            
            self.dhcp_servers[server_id] = dhcp_server
            self._save_data('dhcp_servers')
            logger.info(f"Created DHCP server: {server_id} for network {network_id}")
            return True, dhcp_server, "DHCP server created successfully"
        
        except Exception as e:
            logger.error(f"Error creating DHCP server: {e}")
            return False, None, str(e)
    
    def list_dhcp_servers(self) -> List[DHCPServerConfig]:
        """List all DHCP servers"""
        return list(self.dhcp_servers.values())
    
    def get_dhcp_leases(self, server_id: str) -> Tuple[bool, List[DHCPLease], str]:
        """Get DHCP leases for a server"""
        try:
            server = self.dhcp_servers.get(server_id)
            if not server:
                return False, [], "DHCP server not found"
            
            # Collect leases from devices connected to this network
            leases = []
            for device in self.devices.values():
                for iface in device.interfaces:
                    network = self.networks.get(iface.network_id)
                    if network and network.id == server.network_id:
                        if iface.dhcp_enabled and iface.ip_address:
                            lease = DHCPLease(
                                ip_address=iface.ip_address,
                                mac_address=iface.mac_address,
                                hostname=device.name,
                                lease_time=server.lease_time,
                                expires_at=device.created_at + timedelta(seconds=server.lease_time),
                                status="active"
                            )
                            leases.append(lease)
            
            return True, leases, "Leases retrieved successfully"
        
        except Exception as e:
            logger.error(f"Error getting DHCP leases: {e}")
            return False, [], str(e)
    
    # ===== Device Management =====
    
    def create_device(self, name: str, device_type: DeviceType, 
                     network_configs: List[Dict]) -> Tuple[bool, VirtualDevice, str]:
        """Create a virtual device"""
        try:
            device_id = f"dev_{uuid.uuid4().hex[:8]}"
            interfaces = []
            
            # Create interfaces for each network
            for idx, config in enumerate(network_configs):
                network_id = config.get('network_id')
                network = self.get_network(network_id)  # Use get_network to include predefined
                
                if not network:
                    return False, None, f"Network {network_id} not found"
                
                # Generate MAC address
                mac_address = self._generate_mac()
                
                ip_address = None
                dhcp_enabled = config.get('dhcp_enabled', False)
                
                if not dhcp_enabled and 'ip_address' in config:
                    # Validate manual IP is in the network
                    ip_address = config['ip_address']
                    if not self._validate_ip_in_subnet(ip_address, network.subnet):
                        return False, None, f"IP {ip_address} not in subnet {network.subnet}"
                elif dhcp_enabled:
                    # Assign DHCP IP from range
                    dhcp_server = None
                    for srv in self.dhcp_servers.values():
                        if srv.network_id == network_id:
                            dhcp_server = srv
                            break
                    
                    if not dhcp_server:
                        return False, None, f"No DHCP server for network {network_id}. Create one first."
                    
                    ip_address = self._allocate_dhcp_ip(dhcp_server)
                
                interface = DeviceInterface(
                    name=f"eth{idx}",
                    network_id=network_id,
                    mac_address=mac_address,
                    ip_address=ip_address,
                    dhcp_enabled=dhcp_enabled,
                    status="up"
                )
                interfaces.append(interface)
            
            device = VirtualDevice(
                id=device_id,
                name=name,
                device_type=device_type,
                interfaces=interfaces,
                status="running"
            )
            
            self.devices[device_id] = device
            self._save_data('devices')
            logger.info(f"Created device: {device_id} ({name}) - {device_type.value}")
            return True, device, "Device created successfully"
        
        except Exception as e:
            logger.error(f"Error creating device: {e}")
            return False, None, str(e)
    
    def list_devices(self) -> List[VirtualDevice]:
        """List all devices"""
        return list(self.devices.values())
    
    def get_device(self, device_id: str) -> Optional[VirtualDevice]:
        """Get device by ID"""
        return self.devices.get(device_id)
    
    def assign_manual_ip(self, device_id: str, interface_name: str, 
                        ip_address: str, network_id: str) -> Tuple[bool, str]:
        """Manually assign IP to device interface"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False, "Device not found"
            
            # Find interface
            interface = None
            for iface in device.interfaces:
                if iface.name == interface_name:
                    interface = iface
                    break
            
            if not interface:
                return False, f"Interface {interface_name} not found"
            
            # Verify network matches
            if interface.network_id != network_id:
                return False, "Interface not connected to specified network"
            
            # Validate IP is in network
            network = self.networks.get(network_id)
            if not network:
                return False, "Network not found"
            
            if not self._validate_ip_in_subnet(ip_address, network.subnet):
                return False, f"IP {ip_address} not in subnet {network.subnet}"
            
            # Check for IP conflicts
            for dev in self.devices.values():
                for iface in dev.interfaces:
                    if iface.ip_address == ip_address and dev.id != device_id:
                        return False, f"IP {ip_address} already assigned to another device"
            
            # Assign IP
            interface.ip_address = ip_address
            interface.dhcp_enabled = False
            device.last_packet_sent = datetime.now()
            
            self._save_data('devices')
            logger.info(f"Assigned IP {ip_address} to {device_id}/{interface_name}")
            return True, "IP assigned successfully"
        
        except Exception as e:
            logger.error(f"Error assigning IP: {e}")
            return False, str(e)
    
    def delete_device(self, device_id: str) -> Tuple[bool, str]:
        """Delete a device"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False, "Device not found"
            
            # Stop traffic patterns
            for pattern_id in device.active_traffic_patterns:
                self.stop_traffic_pattern(pattern_id)
            
            if device_id in self.devices:
                del self.devices[device_id]
                self._save_data('devices')
                logger.info(f"Deleted device: {device_id}")
                return True, "Device deleted successfully"
            return False, "Device not found"
        
        except Exception as e:
            logger.error(f"Error deleting device: {e}")
            return False, str(e)
    
    # ===== Traffic Generation =====
    
    def start_traffic_patterns(self, device_id: str, 
                              patterns: List[TrafficPattern]) -> Tuple[bool, List[str], str]:
        """Start traffic generation from a device"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False, [], "Device not found"
            
            pattern_ids = []
            for pattern in patterns:
                pattern_id = f"pat_{uuid.uuid4().hex[:8]}"
                
                traffic_instance = TrafficPatternInstance(
                    id=pattern_id,
                    device_id=device_id,
                    pattern=pattern,
                    status="active"
                )
                
                self.traffic_patterns[pattern_id] = traffic_instance
                device.active_traffic_patterns.append(pattern_id)
                pattern_ids.append(pattern_id)
                
                # Start traffic generation thread
                self._start_traffic_thread(pattern_id)
            
            self._save_data('traffic_patterns')
            self._save_data('devices')
            logger.info(f"Started {len(pattern_ids)} traffic patterns for device {device_id}")
            return True, pattern_ids, "Traffic patterns started successfully"
        
        except Exception as e:
            logger.error(f"Error starting traffic patterns: {e}")
            return False, [], str(e)
    
    def _start_traffic_thread(self, pattern_id: str):
        """Start a thread to generate traffic for a pattern"""
        def generate_traffic():
            try:
                pattern_instance = self.traffic_patterns.get(pattern_id)
                if not pattern_instance:
                    return
                
                pattern = pattern_instance.pattern
                start_time = time.time()
                
                while pattern_instance.status == "active":
                    # Simulate packet generation based on pattern type
                    if pattern.pattern_type == "http":
                        self._generate_http_traffic(pattern_instance)
                    elif pattern.pattern_type == "dns":
                        self._generate_dns_traffic(pattern_instance)
                    elif pattern.pattern_type == "ssh":
                        self._generate_ssh_traffic(pattern_instance)
                    elif pattern.pattern_type == "icmp":
                        self._generate_icmp_traffic(pattern_instance)
                    elif pattern.pattern_type == "ftp":
                        self._generate_ftp_traffic(pattern_instance)
                    else:
                        self._generate_custom_traffic(pattern_instance)
                    
                    # Check duration
                    if pattern.duration and (time.time() - start_time) > pattern.duration:
                        pattern_instance.status = "stopped"
                        break
                    
                    # Wait for next packet
                    time.sleep(pattern.frequency)
                
                logger.info(f"Traffic pattern {pattern_id} completed. Sent {pattern_instance.packets_sent} packets")
                self._save_data('traffic_patterns')
            
            except Exception as e:
                logger.error(f"Error in traffic generation thread: {e}")
                pattern_instance = self.traffic_patterns.get(pattern_id)
                if pattern_instance:
                    pattern_instance.status = "stopped"
        
        thread = threading.Thread(target=generate_traffic, daemon=True)
        thread.start()
        self.traffic_threads[pattern_id] = thread
        logger.info(f"Started traffic generation thread for pattern {pattern_id}")
    
    def _generate_http_traffic(self, pattern_instance: TrafficPatternInstance):
        """Generate HTTP traffic"""
        # This would send HTTP packets
        pattern_instance.packets_sent += 1
        pattern_instance.bytes_sent += pattern_instance.pattern.packet_size
        pattern_instance.last_sent_at = datetime.now()
    
    def _generate_dns_traffic(self, pattern_instance: TrafficPatternInstance):
        """Generate DNS traffic"""
        pattern_instance.packets_sent += 1
        pattern_instance.bytes_sent += pattern_instance.pattern.packet_size
        pattern_instance.last_sent_at = datetime.now()
    
    def _generate_ssh_traffic(self, pattern_instance: TrafficPatternInstance):
        """Generate SSH traffic"""
        pattern_instance.packets_sent += 1
        pattern_instance.bytes_sent += pattern_instance.pattern.packet_size
        pattern_instance.last_sent_at = datetime.now()
    
    def _generate_icmp_traffic(self, pattern_instance: TrafficPatternInstance):
        """Generate ICMP/ping traffic"""
        pattern_instance.packets_sent += 1
        pattern_instance.bytes_sent += pattern_instance.pattern.packet_size
        pattern_instance.last_sent_at = datetime.now()
    
    def _generate_ftp_traffic(self, pattern_instance: TrafficPatternInstance):
        """Generate FTP traffic"""
        pattern_instance.packets_sent += 1
        pattern_instance.bytes_sent += pattern_instance.pattern.packet_size
        pattern_instance.last_sent_at = datetime.now()
    
    def _generate_custom_traffic(self, pattern_instance: TrafficPatternInstance):
        """Generate custom traffic"""
        pattern_instance.packets_sent += 1
        pattern_instance.bytes_sent += pattern_instance.pattern.packet_size
        pattern_instance.last_sent_at = datetime.now()
    
    def stop_traffic_pattern(self, pattern_id: str) -> Tuple[bool, str]:
        """Stop a traffic pattern"""
        try:
            pattern = self.traffic_patterns.get(pattern_id)
            if not pattern:
                return False, "Pattern not found"
            
            pattern.status = "stopped"
            
            # Remove from device's active patterns
            device = self.devices.get(pattern.device_id)
            if device and pattern_id in device.active_traffic_patterns:
                device.active_traffic_patterns.remove(pattern_id)
            
            self._save_data('traffic_patterns')
            self._save_data('devices')
            logger.info(f"Stopped traffic pattern {pattern_id}")
            return True, "Pattern stopped successfully"
        
        except Exception as e:
            logger.error(f"Error stopping pattern: {e}")
            return False, str(e)
    
    def get_traffic_stats(self, pattern_id: str) -> Tuple[bool, Optional[TrafficPatternInstance], str]:
        """Get statistics for a traffic pattern"""
        try:
            pattern = self.traffic_patterns.get(pattern_id)
            if not pattern:
                return False, None, "Pattern not found"
            return True, pattern, "Stats retrieved successfully"
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return False, None, str(e)
    
    # ===== Helper Methods =====
    
    def _validate_subnet(self, subnet: str) -> bool:
        """Validate CIDR subnet format"""
        try:
            parts = subnet.split('/')
            if len(parts) != 2:
                return False
            ip_parts = parts[0].split('.')
            if len(ip_parts) != 4:
                return False
            for part in ip_parts:
                if not 0 <= int(part) <= 255:
                    return False
            prefix = int(parts[1])
            if not 0 <= prefix <= 32:
                return False
            return True
        except:
            return False
    
    def _validate_ip_in_subnet(self, ip: str, subnet: str) -> bool:
        """Validate IP is in subnet"""
        try:
            from ipaddress import IPv4Address, IPv4Network
            return IPv4Address(ip) in IPv4Network(subnet, strict=False)
        except:
            return False
    
    def _generate_mac(self) -> str:
        """Generate a random MAC address"""
        import random
        return f"02:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
    
    def _allocate_dhcp_ip(self, dhcp_server: DHCPServerConfig) -> Optional[str]:
        """Allocate next available IP from DHCP pool"""
        try:
            from ipaddress import IPv4Address
            
            # Get all used IPs
            used_ips = set()
            for device in self.devices.values():
                for iface in device.interfaces:
                    if iface.ip_address:
                        used_ips.add(IPv4Address(iface.ip_address))
            
            # Find next available IP
            start = IPv4Address(dhcp_server.range_start)
            end = IPv4Address(dhcp_server.range_end)
            
            current = start
            while current <= end:
                if current not in used_ips:
                    return str(current)
                current += 1
            
            return None
        except Exception as e:
            logger.error(f"Error allocating DHCP IP: {e}")
            return None


# Global instance
virtual_infra_manager = VirtualInfrastructureManager()
