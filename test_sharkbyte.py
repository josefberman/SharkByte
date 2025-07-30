#!/usr/bin/env python3
"""
Test script for SharkByte PCAP analyzer.
This script demonstrates the functionality without requiring actual PCAP files.
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sharkbyte.analyzer import PCAPAnalyzer
from sharkbyte.pattern_detector import PatternDetector
from sharkbyte.llm_analyzer import LLMAnalyzer
from sharkbyte.visualizer import Visualizer


def create_sample_data():
    """Create sample analysis data for testing."""
    
    # Sample PCAP analysis results
    analysis_results = {
        'files': {
            '/path/to/file1.pcap': {
                'file_path': '/path/to/file1.pcap',
                'file_size_mb': 15.5,
                'total_packets': 5000,
                'protocols': {
                    'TCP': 3000,
                    'HTTP': 1500,
                    'DNS': 500
                },
                'ip_addresses': ['192.168.1.100', '10.0.0.1', '8.8.8.8'],
                'ports': ['80', '443', '53', '22'],
                'key_value_pairs': {
                    'ip.src': ['192.168.1.100', '192.168.1.100', '192.168.1.100'],
                    'ip.dst': ['8.8.8.8', '10.0.0.1', '8.8.8.8'],
                    'tcp.srcport': ['12345', '12346', '12347'],
                    'tcp.dstport': ['80', '443', '53'],
                    'http.host': ['example.com', 'google.com', 'github.com'],
                    'dns.qry.name': ['example.com', 'google.com', 'github.com']
                }
            },
            '/path/to/file2.pcap': {
                'file_path': '/path/to/file2.pcap',
                'file_size_mb': 8.2,
                'total_packets': 3000,
                'protocols': {
                    'TCP': 2000,
                    'HTTP': 800,
                    'DNS': 200
                },
                'ip_addresses': ['192.168.1.100', '10.0.0.1', '1.1.1.1'],
                'ports': ['80', '443', '53', '22'],
                'key_value_pairs': {
                    'ip.src': ['192.168.1.100', '192.168.1.100', '192.168.1.100'],
                    'ip.dst': ['1.1.1.1', '10.0.0.1', '1.1.1.1'],
                    'tcp.srcport': ['12345', '12346', '12347'],
                    'tcp.dstport': ['80', '443', '53'],
                    'http.host': ['example.com', 'stackoverflow.com', 'reddit.com'],
                    'dns.qry.name': ['example.com', 'stackoverflow.com', 'reddit.com']
                }
            }
        },
        'summary': {
            'total_files': 2,
            'total_packets': 8000,
            'total_size_mb': 23.7,
            'common_protocols': {
                'TCP': 5000,
                'HTTP': 2300,
                'DNS': 700
            },
            'all_ip_addresses': ['192.168.1.100', '10.0.0.1', '8.8.8.8', '1.1.1.1'],
            'all_ports': ['80', '443', '53', '22']
        }
    }
    
    return analysis_results


def test_pattern_detection():
    """Test pattern detection functionality."""
    print("Testing pattern detection...")
    
    # Create sample data
    analysis_results = create_sample_data()
    
    # Test pattern detector
    pattern_detector = PatternDetector(similarity_threshold=0.7)
    pattern_results = pattern_detector.detect_patterns(analysis_results)
    
    print(f"Pattern detection results:")
    print(f"  - Common keys: {len(pattern_results.get('common_keys', []))}")
    print(f"  - Hidden identifiers: {len(pattern_results.get('hidden_identifiers', []))}")
    print(f"  - Similar patterns: {len(pattern_results.get('similar_patterns', []))}")
    
    # Print some details
    common_keys = pattern_results.get('common_keys', [])
    if common_keys:
        print(f"\nCommon keys found:")
        for key in common_keys[:5]:
            print(f"  - {key}")
    
    hidden_identifiers = pattern_results.get('hidden_identifiers', [])
    if hidden_identifiers:
        print(f"\nHidden identifiers found:")
        for identifier in hidden_identifiers[:3]:
            print(f"  - Value: {identifier.get('value', 'N/A')}")
            print(f"    Files: {len(identifier.get('files', []))}")
            print(f"    Confidence: {identifier.get('confidence', 0):.2f}")
    
    return pattern_results


def test_visualization():
    """Test visualization functionality."""
    print("\nTesting visualization...")
    
    # Create sample data
    analysis_results = create_sample_data()
    pattern_results = test_pattern_detection()
    
    # Test visualizer
    try:
        visualizer = Visualizer()
        visualizer.create_analysis_visualizations(analysis_results, pattern_results, "test_visualizations")
        print("Visualizations created successfully in 'test_visualizations/' directory")
    except Exception as e:
        print(f"Visualization test failed: {str(e)}")


def test_llm_analysis():
    """Test LLM analysis functionality (without API key)."""
    print("\nTesting LLM analysis (mock)...")
    
    # Create sample data
    pattern_results = test_pattern_detection()
    
    # Test LLM analyzer (will fail without API key, but shows the structure)
    try:
        llm_analyzer = LLMAnalyzer()
        llm_analysis = llm_analyzer.analyze_patterns(pattern_results)
        print("LLM analysis completed successfully")
    except Exception as e:
        print(f"LLM analysis test failed (expected without API key): {str(e)}")
        print("This is expected behavior when OPENAI_API_KEY is not set")


def test_main_functionality():
    """Test the main functionality without requiring PCAP files."""
    print("=" * 60)
    print("SHARKBYTE TEST SCRIPT")
    print("=" * 60)
    
    print("\nThis test script demonstrates SharkByte functionality using sample data.")
    print("It does not require actual PCAP files or OpenAI API key.")
    
    # Test pattern detection
    pattern_results = test_pattern_detection()
    
    # Test visualization
    test_visualization()
    
    # Test LLM analysis
    test_llm_analysis()
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    print("\nTo use SharkByte with real PCAP files:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Set your OpenAI API key: export OPENAI_API_KEY=your_key_here")
    print("3. Run: python main.py --pcap-folder /path/to/pcaps --output results.json")
    print("\nFor more options: python main.py --help")


if __name__ == "__main__":
    test_main_functionality() 