"""
Utility functions for SharkByte PCAP analyzer.
"""

import os
import json
import hashlib
import asyncio
from typing import Dict, List, Any, Tuple
from pathlib import Path
import pandas as pd
from tqdm import tqdm


def find_pcap_files(folder_path: str) -> List[str]:
    """
    Find all PCAP files in the specified folder.
    
    Args:
        folder_path: Path to the folder containing PCAP files
        
    Returns:
        List of PCAP file paths
    """
    pcap_files = []
    folder = Path(folder_path)
    
    if not folder.exists():
        raise FileNotFoundError(f"Folder {folder_path} does not exist")
    
    # Common PCAP file extensions
    pcap_extensions = ['.pcap', '.pcapng', '.cap']
    
    for file_path in folder.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in pcap_extensions:
            pcap_files.append(str(file_path))
    
    return pcap_files


def calculate_hash(data: str) -> str:
    """
    Calculate SHA-256 hash of data.
    
    Args:
        data: String data to hash
        
    Returns:
        SHA-256 hash string
    """
    return hashlib.sha256(data.encode()).hexdigest()


def normalize_value(value: Any) -> str:
    """
    Normalize a value for comparison.
    
    Args:
        value: Value to normalize
        
    Returns:
        Normalized string representation
    """
    if value is None:
        return "null"
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        return value.lower().strip()
    else:
        return str(value).lower().strip()


def calculate_similarity(str1: str, str2: str) -> float:
    """
    Calculate similarity between two strings using Jaccard similarity.
    
    Args:
        str1: First string
        str2: Second string
        
    Returns:
        Similarity score between 0 and 1
    """
    if not str1 or not str2:
        return 0.0
    
    # Convert to sets of characters for Jaccard similarity
    set1 = set(str1.lower())
    set2 = set(str2.lower())
    
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0.0


def extract_key_value_pairs(data: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract key-value pairs from nested dictionary.
    
    Args:
        data: Nested dictionary
        
    Returns:
        Flattened key-value pairs
    """
    result = {}
    
    def flatten_dict(d: Dict[str, Any], prefix: str = ""):
        for key, value in d.items():
            new_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                flatten_dict(value, new_key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        flatten_dict(item, f"{new_key}[{i}]")
                    else:
                        result[f"{new_key}[{i}]"] = normalize_value(item)
            else:
                result[new_key] = normalize_value(value)
    
    flatten_dict(data)
    return result


def save_results(results: Dict[str, Any], output_path: str):
    """
    Save analysis results to JSON file.
    
    Args:
        results: Analysis results dictionary
        output_path: Path to save the JSON file
    """
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)


def load_results(input_path: str) -> Dict[str, Any]:
    """
    Load analysis results from JSON file.
    
    Args:
        input_path: Path to the JSON file
        
    Returns:
        Loaded results dictionary
    """
    with open(input_path, 'r') as f:
        return json.load(f)


def create_progress_bar(description: str, total: int):
    """
    Create a progress bar for long-running operations.
    
    Args:
        description: Description of the operation
        total: Total number of items
        
    Returns:
        tqdm progress bar
    """
    return tqdm(total=total, desc=description, unit="files")


def validate_file_path(file_path: str) -> bool:
    """
    Validate if a file path exists and is readable.
    
    Args:
        file_path: Path to validate
        
    Returns:
        True if file exists and is readable, False otherwise
    """
    try:
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
    except (OSError, IOError):
        return False


def get_file_size_mb(file_path: str) -> float:
    """
    Get file size in megabytes.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File size in MB
    """
    return os.path.getsize(file_path) / (1024 * 1024)


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human-readable string.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"


def ensure_event_loop():
    """
    Ensure an event loop is available in the current thread.
    This is needed for async operations in threaded environments.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # No event loop in current thread, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop 