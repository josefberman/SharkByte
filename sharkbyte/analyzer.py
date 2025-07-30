"""
Core PCAP analyzer for SharkByte.
"""

import pyshark
import pandas as pd
from typing import Dict, List, Any, Optional
from collections import defaultdict
import json
from .utils import (
    normalize_value, 
    extract_key_value_pairs, 
    calculate_hash,
    get_file_size_mb,
    format_bytes
)


class PCAPAnalyzer:
    """
    Analyzes PCAP files to extract packet information and key-value pairs.
    """
    
    def __init__(self):
        self.packet_data = []
        self.key_value_pairs = defaultdict(list)
        self.file_metadata = {}
        
    def analyze_pcap_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a single PCAP file and extract packet information.
        
        Args:
            file_path: Path to the PCAP file
            
        Returns:
            Dictionary containing analysis results
        """
        print(f"Analyzing PCAP file: {file_path}")
        
        try:
            # Open PCAP file
            cap = pyshark.FileCapture(file_path)
            
            file_info = {
                'file_path': file_path,
                'file_size_mb': get_file_size_mb(file_path),
                'total_packets': 0,
                'protocols': defaultdict(int),
                'ip_addresses': set(),
                'ports': set(),
                'packet_data': [],
                'key_value_pairs': defaultdict(list)
            }
            
            packet_count = 0
            max_packets = 10000  # Limit to prevent memory issues
            
            for packet in cap:
                if packet_count >= max_packets:
                    print(f"Reached packet limit ({max_packets}) for {file_path}")
                    break
                    
                packet_info = self._extract_packet_info(packet)
                file_info['packet_data'].append(packet_info)
                
                # Extract key-value pairs
                kv_pairs = self._extract_packet_key_values(packet)
                for key, value in kv_pairs.items():
                    file_info['key_value_pairs'][key].append(value)
                
                # Update statistics
                file_info['total_packets'] += 1
                
                # Track protocols
                if hasattr(packet, 'highest_layer'):
                    file_info['protocols'][packet.highest_layer] += 1
                
                # Track IP addresses
                if hasattr(packet, 'ip'):
                    if hasattr(packet.ip, 'src'):
                        file_info['ip_addresses'].add(packet.ip.src)
                    if hasattr(packet.ip, 'dst'):
                        file_info['ip_addresses'].add(packet.ip.dst)
                
                # Track ports
                if hasattr(packet, 'tcp'):
                    if hasattr(packet.tcp, 'srcport'):
                        file_info['ports'].add(packet.tcp.srcport)
                    if hasattr(packet.tcp, 'dstport'):
                        file_info['ports'].add(packet.tcp.dstport)
                elif hasattr(packet, 'udp'):
                    if hasattr(packet.udp, 'srcport'):
                        file_info['ports'].add(packet.udp.srcport)
                    if hasattr(packet.udp, 'dstport'):
                        file_info['ports'].add(packet.udp.dstport)
                
                packet_count += 1
            
            cap.close()
            
            # Convert sets to lists for JSON serialization
            file_info['ip_addresses'] = list(file_info['ip_addresses'])
            file_info['ports'] = list(file_info['ports'])
            file_info['protocols'] = dict(file_info['protocols'])
            
            print(f"Analyzed {file_info['total_packets']} packets from {file_path}")
            return file_info
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {str(e)}")
            return {
                'file_path': file_path,
                'error': str(e),
                'total_packets': 0,
                'packet_data': [],
                'key_value_pairs': {}
            }
    
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """
        Extract basic information from a packet.
        
        Args:
            packet: PyShark packet object
            
        Returns:
            Dictionary with packet information
        """
        packet_info = {
            'frame_number': getattr(packet, 'frame_info', {}).get('number', 'unknown'),
            'timestamp': getattr(packet, 'frame_info', {}).get('time', 'unknown'),
            'length': getattr(packet, 'frame_info', {}).get('length', 'unknown'),
            'protocols': [],
            'layers': {}
        }
        
        # Extract layer information
        for layer in packet.layers:
            layer_name = layer.layer_name
            packet_info['protocols'].append(layer_name)
            
            # Extract layer fields
            layer_data = {}
            for field_name in layer.field_names:
                try:
                    value = getattr(layer, field_name)
                    layer_data[field_name] = str(value)
                except:
                    continue
            
            packet_info['layers'][layer_name] = layer_data
        
        return packet_info
    
    def _extract_packet_key_values(self, packet) -> Dict[str, str]:
        """
        Extract key-value pairs from a packet.
        
        Args:
            packet: PyShark packet object
            
        Returns:
            Dictionary of key-value pairs
        """
        kv_pairs = {}
        
        for layer in packet.layers:
            layer_name = layer.layer_name
            
            for field_name in layer.field_names:
                try:
                    value = getattr(layer, field_name)
                    key = f"{layer_name}.{field_name}"
                    kv_pairs[key] = normalize_value(value)
                except:
                    continue
        
        return kv_pairs
    
    def analyze_multiple_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        Analyze multiple PCAP files.
        
        Args:
            file_paths: List of PCAP file paths
            
        Returns:
            Dictionary containing analysis results for all files
        """
        results = {
            'files': {},
            'summary': {
                'total_files': len(file_paths),
                'total_packets': 0,
                'total_size_mb': 0,
                'common_protocols': defaultdict(int),
                'all_ip_addresses': set(),
                'all_ports': set()
            }
        }
        
        for file_path in file_paths:
            file_results = self.analyze_pcap_file(file_path)
            results['files'][file_path] = file_results
            
            # Update summary statistics
            if 'error' not in file_results:
                results['summary']['total_packets'] += file_results['total_packets']
                results['summary']['total_size_mb'] += file_results['file_size_mb']
                
                # Update common protocols
                for protocol, count in file_results['protocols'].items():
                    results['summary']['common_protocols'][protocol] += count
                
                # Update IP addresses and ports
                results['summary']['all_ip_addresses'].update(file_results['ip_addresses'])
                results['summary']['all_ports'].update(file_results['ports'])
        
        # Convert sets to lists for JSON serialization
        results['summary']['all_ip_addresses'] = list(results['summary']['all_ip_addresses'])
        results['summary']['all_ports'] = list(results['summary']['all_ports'])
        results['summary']['common_protocols'] = dict(results['summary']['common_protocols'])
        
        return results
    
    def get_key_value_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Get a summary of all key-value pairs across all files.
        
        Args:
            analysis_results: Results from analyze_multiple_files
            
        Returns:
            Dictionary mapping keys to lists of unique values
        """
        key_value_summary = defaultdict(set)
        
        for file_path, file_results in analysis_results['files'].items():
            if 'error' not in file_results:
                for key, values in file_results['key_value_pairs'].items():
                    key_value_summary[key].update(values)
        
        # Convert sets to lists
        return {key: list(values) for key, values in key_value_summary.items()}
    
    def find_common_keys(self, analysis_results: Dict[str, Any]) -> List[str]:
        """
        Find keys that appear in multiple files.
        
        Args:
            analysis_results: Results from analyze_multiple_files
            
        Returns:
            List of keys that appear in multiple files
        """
        key_counts = defaultdict(int)
        
        for file_path, file_results in analysis_results['files'].items():
            if 'error' not in file_results:
                for key in file_results['key_value_pairs'].keys():
                    key_counts[key] += 1
        
        # Return keys that appear in more than one file
        return [key for key, count in key_counts.items() if count > 1] 