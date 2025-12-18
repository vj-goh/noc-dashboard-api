"""
Diagnostics Service
Implements network diagnostic tools: ping, traceroute, port checks, DNS lookups
"""

import re
import logging
from typing import Optional
from app.services.docker_executor import docker_executor
from app.models import (
    PingResponse,
    TracerouteResponse,
    TracerouteHop,
    PortCheckResponse,
    DNSLookupResponse
)
from datetime import datetime

logger = logging.getLogger(__name__)

class DiagnosticsService:
    """Network diagnostics service"""
    
    @staticmethod
    def ping(target: str, count: int = 3, timeout: int = 5) -> PingResponse:
        """
        Execute ping command
        
        Args:
            target: Target IP or hostname
            count: Number of ping packets
            timeout: Timeout per packet
            
        Returns:
            PingResponse with results
        """
        logger.info(f"Pinging {target} with {count} packets")
        
        # Build ping command
        command = ["ping", "-c", str(count), "-W", str(timeout), target]
        
        # Execute command
        success, output = docker_executor.exec_network_command(command, timeout=timeout+5)
        
        if not success:
            return PingResponse(
                success=False,
                target=target,
                packets_sent=count,
                packets_received=0,
                packet_loss_pct=100.0,
                output=output
            )
        
        # Parse ping output
        parsed = DiagnosticsService._parse_ping_output(output)
        
        return PingResponse(
            success=True,
            target=target,
            packets_sent=parsed.get('sent', count),
            packets_received=parsed.get('received', 0),
            packet_loss_pct=parsed.get('loss_pct', 100.0),
            min_rtt=parsed.get('min_rtt'),
            avg_rtt=parsed.get('avg_rtt'),
            max_rtt=parsed.get('max_rtt'),
            output=output
        )
    
    @staticmethod
    def _parse_ping_output(output: str) -> dict:
        """Parse ping command output"""
        result = {}
        
        # Extract packet statistics
        # Example: "3 packets transmitted, 3 received, 0% packet loss"
        packet_pattern = r'(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss'
        packet_match = re.search(packet_pattern, output)
        
        if packet_match:
            result['sent'] = int(packet_match.group(1))
            result['received'] = int(packet_match.group(2))
            result['loss_pct'] = float(packet_match.group(3))
        
        # Extract RTT statistics
        # Example: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
        rtt_pattern = r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms'
        rtt_match = re.search(rtt_pattern, output)
        
        if rtt_match:
            result['min_rtt'] = float(rtt_match.group(1))
            result['avg_rtt'] = float(rtt_match.group(2))
            result['max_rtt'] = float(rtt_match.group(3))
        
        return result
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30, timeout: int = 5) -> TracerouteResponse:
        """
        Execute traceroute command
        
        Args:
            target: Target IP or hostname
            max_hops: Maximum number of hops
            timeout: Timeout per hop
            
        Returns:
            TracerouteResponse with hop information
        """
        logger.info(f"Tracing route to {target} (max {max_hops} hops)")
        
        # Build traceroute command
        command = ["traceroute", "-m", str(max_hops), "-w", str(timeout), target]
        
        # Execute command
        success, output = docker_executor.exec_network_command(command, timeout=(max_hops * timeout) + 10)
        
        if not success:
            return TracerouteResponse(
                success=False,
                target=target,
                hops=[],
                output=output
            )
        
        # Parse traceroute output
        hops = DiagnosticsService._parse_traceroute_output(output)
        
        return TracerouteResponse(
            success=True,
            target=target,
            hops=hops,
            output=output
        )
    
    @staticmethod
    def _parse_traceroute_output(output: str) -> list[TracerouteHop]:
        """Parse traceroute command output"""
        hops = []
        
        # Parse each line
        # Example: " 1  10.0.1.1 (10.0.1.1)  0.123 ms  0.456 ms  0.789 ms"
        for line in output.split('\n'):
            hop_pattern = r'\s*(\d+)\s+([^\s]+)\s+\(([^\)]+)\)\s+([\d.]+)\s+ms'
            match = re.search(hop_pattern, line)
            
            if match:
                hop = TracerouteHop(
                    hop_number=int(match.group(1)),
                    hostname=match.group(2) if match.group(2) != match.group(3) else None,
                    ip_address=match.group(3),
                    rtt=float(match.group(4))
                )
                hops.append(hop)
            elif re.match(r'\s*\d+\s+\*', line):
                # Timeout hop
                hop_num = int(line.strip().split()[0])
                hops.append(TracerouteHop(
                    hop_number=hop_num,
                    ip_address=None,
                    hostname=None,
                    rtt=None
                ))
        
        return hops
    
    @staticmethod
    def check_port(host: str, port: int, protocol: str = "tcp") -> PortCheckResponse:
        """
        Check if a port is open
        
        Args:
            host: Target host
            port: Port number
            protocol: Protocol (tcp or udp)
            
        Returns:
            PortCheckResponse with port status
        """
        logger.info(f"Checking {protocol} port {port} on {host}")
        
        if protocol == "tcp":
            # Use netcat for TCP
            command = ["nc", "-zv", "-w", "2", host, str(port)]
        else:
            # Use netcat for UDP
            command = ["nc", "-zuv", "-w", "2", host, str(port)]
        
        success, output = docker_executor.exec_network_command(command, timeout=5)
        
        # Parse output to determine status
        status = "open" if success or "succeeded" in output.lower() else "closed"
        
        # Try to identify service
        service = DiagnosticsService._identify_service(port)
        
        return PortCheckResponse(
            success=True,
            host=host,
            port=port,
            protocol=protocol,
            status=status,
            service=service
        )
    
    @staticmethod
    def _identify_service(port: int) -> Optional[str]:
        """Identify common services by port number"""
        common_ports = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            25: "SMTP",
            53: "DNS",
            179: "BGP",
            1812: "RADIUS Auth",
            1813: "RADIUS Acct",
            2601: "Zebra/FRRouting",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            8000: "HTTP Alt",
            8080: "HTTP Proxy"
        }
        return common_ports.get(port)
    
    @staticmethod
    def dns_lookup(hostname: str, record_type: str = "A") -> DNSLookupResponse:
        """
        Perform DNS lookup
        
        Args:
            hostname: Hostname to resolve
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            DNSLookupResponse with resolution results
        """
        logger.info(f"DNS lookup for {hostname} (type: {record_type})")
        
        start_time = datetime.now()
        
        # Use dig for DNS lookup
        command = ["dig", "+short", hostname, record_type]
        
        success, output = docker_executor.exec_network_command(command, timeout=10)
        
        query_time = (datetime.now() - start_time).total_seconds() * 1000  # milliseconds
        
        if not success or not output.strip():
            return DNSLookupResponse(
                success=False,
                hostname=hostname,
                record_type=record_type,
                answers=[],
                query_time=query_time,
                nameserver="10.0.1.40"  # Our DNS server
            )
        
        # Parse answers
        answers = [line.strip() for line in output.split('\n') if line.strip()]
        
        return DNSLookupResponse(
            success=True,
            hostname=hostname,
            record_type=record_type,
            answers=answers,
            query_time=query_time,
            nameserver="10.0.1.40"  # Our DNS server
        )

# Create global instance
diagnostics_service = DiagnosticsService()