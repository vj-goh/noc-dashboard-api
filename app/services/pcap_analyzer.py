"""
PCAP Analyzer Service
Analyzes network packet capture files using Scapy
"""

from pathlib import Path
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP, IPv6
except ImportError:
    logger.warning("Scapy not installed - PCAP analysis will be limited")
    rdpcap = None


class PCAPAnalyzer:
    """Analyze PCAP files for network metrics"""
    
    def __init__(self, pcap_file: Path):
        """
        Initialize PCAP analyzer
        
        Args:
            pcap_file: Path to PCAP file
        """
        if not rdpcap:
            raise RuntimeError("Scapy is not installed")
        
        self.pcap_file = Path(pcap_file)
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        logger.info(f"Loading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(str(self.pcap_file))
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            raise
        
        logger.info(f"Loaded {len(self.packets)} packets")
        self.stats = self._analyze()
    
    def _analyze(self):
        """Extract key metrics from packets"""
        stats = {
            'total_packets': len(self.packets),
            'packet_size_bytes': sum(len(p) for p in self.packets),
            'duration_seconds': self._get_duration(),
            'protocols': defaultdict(int),
            'conversations': defaultdict(lambda: {'packets': 0, 'bytes': 0}),
            'dns_queries': Counter(),
            'tcp_streams': defaultdict(list),
            'udp_streams': defaultdict(list),
            'icmp_packets': 0,
            'ipv4_packets': 0,
            'ipv6_packets': 0,
        }
        
        for packet in self.packets:
            try:
                # IP layer analysis
                if IP in packet:
                    stats['ipv4_packets'] += 1
                    stats['protocols']['IPv4'] += 1
                    src = packet[IP].src
                    dst = packet[IP].dst
                    conv_key = f"{src} → {dst}"
                    stats['conversations'][conv_key]['packets'] += 1
                    stats['conversations'][conv_key]['bytes'] += len(packet)
                    
                    # Transport layer
                    if TCP in packet:
                        stats['protocols']['TCP'] += 1
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        tcp_flow = f"{src}:{sport} → {dst}:{dport}"
                        stats['tcp_streams'][tcp_flow].append(packet)
                        
                    elif UDP in packet:
                        stats['protocols']['UDP'] += 1
                        dport = packet[UDP].dport
                        udp_flow = f"{src} → {dst}:{dport}"
                        stats['udp_streams'][udp_flow].append(packet)
                        
                    elif ICMP in packet:
                        stats['protocols']['ICMP'] += 1
                        stats['icmp_packets'] += 1
                
                elif IPv6 in packet:
                    stats['ipv6_packets'] += 1
                    stats['protocols']['IPv6'] += 1
                
                # Application layer protocols
                if DNS in packet:
                    stats['protocols']['DNS'] += 1
                    try:
                        if packet[DNS].qd:
                            query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                            stats['dns_queries'][query] += 1
                    except Exception as e:
                        logger.debug(f"Error parsing DNS query: {e}")
                
                if ARP in packet:
                    stats['protocols']['ARP'] += 1
            
            except Exception as e:
                logger.debug(f"Error analyzing packet: {e}")
                continue
        
        return stats
    
    def _get_duration(self):
        """Calculate capture duration"""
        if not self.packets or len(self.packets) < 2:
            return 0
        try:
            return float(self.packets[-1].time - self.packets[0].time)
        except:
            return 0
    
    def get_summary(self):
        """Return human-readable summary"""
        duration = self.stats['duration_seconds']
        total_packets = self.stats['total_packets']
        
        return {
            'total_packets': total_packets,
            'capture_duration': f"{duration:.2f}s",
            'packets_per_second': round(total_packets / max(duration, 1)),
            'total_data': f"{self.stats['packet_size_bytes'] / 1024:.2f} KB",
            'protocols': dict(self.stats['protocols']),
            'unique_dns_queries': len(self.stats['dns_queries']),
            'tcp_flows': len(self.stats['tcp_streams']),
            'udp_flows': len(self.stats['udp_streams']),
            'ipv4_packets': self.stats['ipv4_packets'],
            'ipv6_packets': self.stats['ipv6_packets'],
            'icmp_packets': self.stats['icmp_packets']
        }
    
    def get_protocol_breakdown(self):
        """Return percentage breakdown of protocols"""
        total = sum(self.stats['protocols'].values())
        if total == 0:
            return {}
        
        return {
            proto: round((count / total) * 100, 2)
            for proto, count in self.stats['protocols'].items()
        }
    
    def get_conversations(self, limit=20):
        """Get top talkers by bytes transferred"""
        sorted_convs = sorted(
            self.stats['conversations'].items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        return sorted_convs[:limit]
    
    def get_dns_queries(self, limit=50):
        """Get DNS queries"""
        return dict(self.stats['dns_queries'].most_common(limit))
    
    def get_tcp_flows(self, limit=20):
        """Get top TCP flows"""
        flows = []
        for flow, packets in self.stats['tcp_streams'].items():
            if packets:
                flows.append({
                    'flow': flow,
                    'packet_count': len(packets),
                    'bytes': sum(len(p) for p in packets)
                })
        
        return sorted(flows, key=lambda x: x['bytes'], reverse=True)[:limit]
    
    def export_json(self):
        """Export complete analysis as JSON"""
        conversations = self.get_conversations()
        
        return {
            'summary': self.get_summary(),
            'protocol_breakdown': self.get_protocol_breakdown(),
            'conversations': [
                {'src_dst': k, **v} for k, v in conversations
            ],
            'dns_queries': self.get_dns_queries(50),
            'tcp_flows': self.get_tcp_flows(20),
            'file_path': str(self.pcap_file),
            'file_size': self.pcap_file.stat().st_size
        }
