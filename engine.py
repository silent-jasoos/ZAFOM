# -*- coding: utf-8 -*-
"""
===========================================
ZAFOM - Zee's Analyzer For Online Monitoring
Module: Core Engine
Author: Zeeshan
Version: 2.1
===========================================
"""

import threading
import time
import binascii
import json
from queue import Queue
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, ARP, wrpcap, get_if_list


class PacketEngine:
    """Core packet capture and processing engine."""
    
    def __init__(self, error_callback=None):
        self.packet_count = 0
        self.packets_store = []
        self.packet_queue = Queue(maxsize=5000)  # Limit queue size
        self.sniff_thread = None
        self.is_sniffing = False
        self.is_paused = False
        self.filter_protocol = "ALL"
        self.filter_port = ""
        self.error_callback = error_callback
        self.max_packets = 10000  # Memory limit
        self.selected_interface = None
        
        # Statistics tracking
        self.stats = {
            'total_bytes': 0,
            'protocol_count': defaultdict(int),
            'start_time': None,
            'end_time': None
        }
        
        # Thread safety
        self.store_lock = threading.Lock()
        
    def get_available_interfaces(self):
        """Get list of available network interfaces."""
        try:
            return get_if_list()
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []
    
    def set_interface(self, interface):
        """Set the network interface to capture on."""
        self.selected_interface = interface
        
    def start_capture(self):
        """Start packet capture in a separate thread."""
        if not self.is_sniffing:
            self.is_sniffing = True
            self.is_paused = False
            self.stats['start_time'] = time.time()
            self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self.sniff_thread.start()
            return True
        return False
    
    def pause_capture(self):
        """Pause packet capture without stopping."""
        self.is_paused = True
        return True
    
    def resume_capture(self):
        """Resume paused packet capture."""
        self.is_paused = False
        return True
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_sniffing = False
        self.is_paused = False
        self.stats['end_time'] = time.time()
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
        return True
    
    def clear_packets(self):
        """Clear all captured packets."""
        with self.store_lock:
            self.packet_count = 0
            self.packets_store.clear()
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except:
                    break
            # Reset statistics
            self.stats = {
                'total_bytes': 0,
                'protocol_count': defaultdict(int),
                'start_time': None,
                'end_time': None
            }
    
    def set_filter(self, protocol="ALL", port=""):
        """Set protocol and port filters."""
        # Validate port
        if port:
            try:
                port_num = int(port)
                if not (0 <= port_num <= 65535):
                    if self.error_callback:
                        self.error_callback("Port must be between 0-65535")
                    return False
            except ValueError:
                if self.error_callback:
                    self.error_callback("Invalid port number")
                return False
        
        self.filter_protocol = protocol
        self.filter_port = port
        return True
    
    def get_statistics(self):
        """Get capture statistics."""
        with self.store_lock:
            duration = 0
            if self.stats['start_time']:
                end = self.stats['end_time'] or time.time()
                duration = end - self.stats['start_time']
            
            return {
                'total_packets': self.packet_count,
                'total_bytes': self.stats['total_bytes'],
                'protocol_breakdown': dict(self.stats['protocol_count']),
                'duration': duration,
                'packets_per_second': self.packet_count / duration if duration > 0 else 0,
                'bytes_per_second': self.stats['total_bytes'] / duration if duration > 0 else 0
            }
    
    def _sniff_packets(self):
        """Internal method to sniff packets."""
        try:
            kwargs = {
                'prn': self._process_packet,
                'store': False,
                'stop_filter': lambda x: not self.is_sniffing
            }
            
            # Add interface if specified
            if self.selected_interface:
                kwargs['iface'] = self.selected_interface
            
            sniff(**kwargs)
        except PermissionError:
            error_msg = "Permission denied. Run with sudo/administrator privileges."
            print(f"ERROR: {error_msg}")
            if self.error_callback:
                self.error_callback(error_msg)
            self.is_sniffing = False
        except Exception as e:
            error_msg = f"Capture failed: {str(e)}"
            print(f"Sniffing error: {error_msg}")
            if self.error_callback:
                self.error_callback(error_msg)
            self.is_sniffing = False
    
    def _process_packet(self, pkt):
        """Process captured packet and add to queue."""
        if not self.is_sniffing or self.is_paused:
            return
        
        # Apply filters
        if not self._apply_filters(pkt):
            return
        
        if IP in pkt or ARP in pkt:
            try:
                self.packet_queue.put(pkt, block=False)
            except:
                # Queue full, skip packet
                pass
    
    def _apply_filters(self, pkt):
        """Apply protocol and port filters to packet."""
        # Protocol filter
        if self.filter_protocol != "ALL":
            if self.filter_protocol == "TCP" and TCP not in pkt:
                return False
            elif self.filter_protocol == "UDP" and UDP not in pkt:
                return False
            elif self.filter_protocol == "DNS" and DNS not in pkt:
                return False
            elif self.filter_protocol == "ICMP" and ICMP not in pkt:
                return False
            elif self.filter_protocol == "ARP" and ARP not in pkt:
                return False
        
        # Port filter
        if self.filter_port:
            try:
                port = int(self.filter_port)
                if TCP in pkt:
                    if pkt[TCP].sport != port and pkt[TCP].dport != port:
                        return False
                elif UDP in pkt:
                    if pkt[UDP].sport != port and pkt[UDP].dport != port:
                        return False
                else:
                    return False
            except ValueError:
                pass
        
        return True
    
    def get_next_packet(self):
        """Get next packet from queue (non-blocking)."""
        if not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                self.packet_count += 1
                return self._parse_packet(pkt)
            except:
                pass
        return None
    
    def _parse_packet(self, pkt):
        """Parse packet and extract relevant information."""
        time_str = time.strftime("%H:%M:%S")
        
        # Update statistics
        packet_length = len(pkt)
        with self.store_lock:
            self.stats['total_bytes'] += packet_length
        
        # Handle ARP packets
        if ARP in pkt:
            with self.store_lock:
                # Apply memory limit
                if len(self.packets_store) >= self.max_packets:
                    self.packets_store.pop(0)
                self.packets_store.append(pkt)
                self.stats['protocol_count']['ARP'] += 1
            
            return {
                "number": self.packet_count,
                "time": time_str,
                "source": pkt[ARP].psrc,
                "destination": pkt[ARP].pdst,
                "protocol": "ARP",
                "length": packet_length,
                "info": f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}",
                "packet": pkt
            }
        
        # Handle IP packets
        if IP not in pkt:
            return None
        
        src = pkt[IP].src
        dst = pkt[IP].dst
        length = packet_length
        proto = "OTHER"
        info = ""
        
        # Detect protocols with enhanced information
        if DNS in pkt:
            proto = "DNS"
            try:
                if pkt.haslayer(DNS) and pkt[DNS].qd:
                    query_name = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                    info = f"Query: {query_name}"
                else:
                    info = "DNS Response"
            except Exception:
                info = "DNS Packet"
        elif ICMP in pkt:
            proto = "ICMP"
            try:
                icmp_type = pkt[ICMP].type
                icmp_code = pkt[ICMP].code
                info = f"Type {icmp_type}, Code {icmp_code}"
            except Exception:
                info = "ICMP Packet"
        elif TCP in pkt:
            proto = "TCP"
            try:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                info = f"{sport} → {dport} [{flags}]"
            except Exception:
                info = "TCP Packet"
        elif UDP in pkt:
            proto = "UDP"
            try:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                info = f"{sport} → {dport}"
            except Exception:
                info = "UDP Packet"
        
        with self.store_lock:
            # Apply memory limit
            if len(self.packets_store) >= self.max_packets:
                self.packets_store.pop(0)
            self.packets_store.append(pkt)
            self.stats['protocol_count'][proto] += 1
        
        return {
            "number": self.packet_count,
            "time": time_str,
            "source": src,
            "destination": dst,
            "protocol": proto,
            "length": length,
            "info": info,
            "packet": pkt
        }
    
    def search_packets(self, search_term):
        """Search packets by IP address, protocol, or port."""
        results = []
        search_term = search_term.lower().strip()
        
        with self.store_lock:
            for i, pkt in enumerate(self.packets_store):
                # Search in IP addresses
                if IP in pkt:
                    if search_term in pkt[IP].src.lower() or search_term in pkt[IP].dst.lower():
                        results.append(i)
                        continue
                
                # Search in ARP addresses
                if ARP in pkt:
                    if search_term in pkt[ARP].psrc.lower() or search_term in pkt[ARP].pdst.lower():
                        results.append(i)
                        continue
                
                # Search by port
                try:
                    port_num = int(search_term)
                    if TCP in pkt:
                        if pkt[TCP].sport == port_num or pkt[TCP].dport == port_num:
                            results.append(i)
                            continue
                    elif UDP in pkt:
                        if pkt[UDP].sport == port_num or pkt[UDP].dport == port_num:
                            results.append(i)
                            continue
                except ValueError:
                    pass
        
        return results
    
    def get_packet_details(self, index):
        """Get detailed information for a specific packet."""
        with self.store_lock:
            if 0 <= index < len(self.packets_store):
                pkt = self.packets_store[index]
                return pkt.show(dump=True)
        return "Packet not found"
    
    def get_packet_hex(self, index):
        """Get hexadecimal representation of packet."""
        with self.store_lock:
            if 0 <= index < len(self.packets_store):
                pkt = self.packets_store[index]
                raw = bytes(pkt)
                hex_data = binascii.hexlify(raw).decode()
                
                # Format: 16 bytes per row, space-separated
                formatted = []
                for i in range(0, len(hex_data), 32):  # 32 hex chars = 16 bytes
                    row = hex_data[i:i+32]
                    spaced = " ".join(row[j:j+2] for j in range(0, len(row), 2))
                    formatted.append(f"{i//2:04x}  {spaced}")
                
                return "\n".join(formatted)
        return "Packet not found"
    
    def export_pcap(self, filename):
        """Export captured packets to PCAP file."""
        try:
            with self.store_lock:
                if self.packets_store:
                    wrpcap(filename, self.packets_store)
                    return True, f"Exported {len(self.packets_store)} packets to {filename}"
            return False, "No packets to export"
        except Exception as e:
            return False, f"Export failed: {str(e)}"
    
    def export_json(self, filename):
        """Export packet summary to JSON file."""
        try:
            with self.store_lock:
                if not self.packets_store:
                    return False, "No packets to export"
                
                packets_json = []
                for i, pkt in enumerate(self.packets_store):
                    packet_info = {
                        "number": i + 1,
                        "timestamp": time.time(),
                        "length": len(pkt),
                        "summary": pkt.summary()
                    }
                    
                    if IP in pkt:
                        packet_info["source"] = pkt[IP].src
                        packet_info["destination"] = pkt[IP].dst
                    elif ARP in pkt:
                        packet_info["source"] = pkt[ARP].psrc
                        packet_info["destination"] = pkt[ARP].pdst
                    
                    packets_json.append(packet_info)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(packets_json, f, indent=2)
            
            return True, f"Exported {len(packets_json)} packets to {filename}"
        except Exception as e:
            return False, f"Export failed: {str(e)}"
    
    def export_txt(self, filename):
        """Export packet details to text file."""
        try:
            with self.store_lock:
                if not self.packets_store:
                    return False, "No packets to export"
                
                packet_list = list(self.packets_store)  # Copy for safe iteration
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ZAFOM - Packet Capture Export\n")
                f.write(f"Total Packets: {len(packet_list)}\n")
                f.write(f"Export Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, pkt in enumerate(packet_list):
                    f.write(f"Packet #{i+1}\n")
                    f.write("-" * 80 + "\n")
                    f.write(pkt.show(dump=True))
                    f.write("\n" + "=" * 80 + "\n\n")
            
            return True, f"Exported {len(packet_list)} packets to {filename}"
        except Exception as e:
            return False, f"Export failed: {str(e)}"