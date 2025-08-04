"""
Pattern detection for SharkByte PCAP analyzer.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Tuple, Set
from collections import defaultdict, Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
import re
import asyncio
from .utils import calculate_similarity, normalize_value, ensure_event_loop


class PatternDetector:
    """
    Detects patterns and similarities in key-value pairs across PCAP files.
    """
    
    def __init__(self, similarity_threshold: float = 0.8):
        self.similarity_threshold = similarity_threshold
        self.patterns = []
        self.similarity_matrix = None
        
    def detect_patterns(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect patterns across multiple PCAP files.
        
        Args:
            analysis_results: Results from PCAPAnalyzer.analyze_multiple_files
            
        Returns:
            Dictionary containing detected patterns
        """
        print("Detecting patterns across PCAP files...")
        
        # Handle async issues in threaded environment
        ensure_event_loop()
        
        # Extract key-value pairs from all files
        all_key_values = self._extract_all_key_values(analysis_results)
        
        # Find common keys
        common_keys = self._find_common_keys(all_key_values)
        
        # Analyze value patterns for common keys
        value_patterns = self._analyze_value_patterns(all_key_values, common_keys)
        
        # Detect similar patterns
        similar_patterns = self._detect_similar_patterns(all_key_values)
        
        # Find hidden identifiers
        hidden_identifiers = self._find_hidden_identifiers(all_key_values)
        
        # Cluster similar values
        value_clusters = self._cluster_similar_values(all_key_values)
        
        results = {
            'common_keys': common_keys,
            'value_patterns': value_patterns,
            'similar_patterns': similar_patterns,
            'hidden_identifiers': hidden_identifiers,
            'value_clusters': value_clusters,
            'statistics': self._calculate_pattern_statistics(all_key_values)
        }
        
        return results
    
    def _extract_all_key_values(self, analysis_results: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
        """
        Extract all key-value pairs from all files.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Dictionary mapping file paths to key-value pairs
        """
        all_key_values = {}
        
        for file_path, file_results in analysis_results['files'].items():
            if 'error' not in file_results:
                all_key_values[file_path] = file_results['key_value_pairs']
        
        return all_key_values
    
    def _find_common_keys(self, all_key_values: Dict[str, Dict[str, List[str]]]) -> List[str]:
        """
        Find keys that appear in multiple files.
        
        Args:
            all_key_values: Key-value pairs from all files
            
        Returns:
            List of common keys
        """
        key_counts = Counter()
        
        for file_key_values in all_key_values.values():
            for key in file_key_values.keys():
                key_counts[key] += 1
        
        # Return keys that appear in more than one file
        return [key for key, count in key_counts.items() if count > 1]
    
    def _analyze_value_patterns(self, all_key_values: Dict[str, Dict[str, List[str]]], 
                               common_keys: List[str]) -> Dict[str, Any]:
        """
        Analyze patterns in values for common keys.
        
        Args:
            all_key_values: Key-value pairs from all files
            common_keys: List of common keys
            
        Returns:
            Dictionary containing value pattern analysis
        """
        value_patterns = {}
        
        for key in common_keys:
            all_values = []
            file_values = {}
            
            # Collect all values for this key
            for file_path, file_key_values in all_key_values.items():
                if key in file_key_values:
                    values = file_key_values[key]
                    all_values.extend(values)
                    file_values[file_path] = values
            
            # Analyze value patterns
            unique_values = list(set(all_values))
            value_counts = Counter(all_values)
            
            # Check for patterns in values
            patterns = self._find_value_patterns(unique_values)
            
            value_patterns[key] = {
                'total_values': len(all_values),
                'unique_values': len(unique_values),
                'most_common_values': value_counts.most_common(10),
                'file_distribution': {file: len(values) for file, values in file_values.items()},
                'patterns': patterns,
                'all_values': all_values,
                'unique_values_list': unique_values
            }
        
        return value_patterns
    
    def _find_value_patterns(self, values: List[str]) -> Dict[str, Any]:
        """
        Find patterns in a list of values.
        
        Args:
            values: List of values to analyze
            
        Returns:
            Dictionary containing detected patterns
        """
        patterns = {
            'numeric_patterns': [],
            'hex_patterns': [],
            'ip_patterns': [],
            'url_patterns': [],
            'email_patterns': [],
            'length_patterns': [],
            'character_patterns': []
        }
        
        for value in values:
            # Numeric patterns
            if re.match(r'^\d+$', value):
                patterns['numeric_patterns'].append(value)
            
            # Hex patterns
            if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
                patterns['hex_patterns'].append(value)
            
            # IP address patterns
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', value):
                patterns['ip_patterns'].append(value)
            
            # URL patterns
            if 'http' in value.lower() or 'www' in value.lower():
                patterns['url_patterns'].append(value)
            
            # Email patterns
            if '@' in value and '.' in value:
                patterns['email_patterns'].append(value)
            
            # Length patterns
            patterns['length_patterns'].append(len(value))
            
            # Character patterns
            char_counts = Counter(value)
            patterns['character_patterns'].append(dict(char_counts))
        
        return patterns
    
    def _detect_similar_patterns(self, all_key_values: Dict[str, Dict[str, List[str]]]) -> List[Dict[str, Any]]:
        """
        Detect similar patterns across different keys.
        
        Args:
            all_key_values: Key-value pairs from all files
            
        Returns:
            List of similar patterns
        """
        similar_patterns = []
        
        # Get all unique keys
        all_keys = set()
        for file_key_values in all_key_values.values():
            all_keys.update(file_key_values.keys())
        
        all_keys = list(all_keys)
        
        # Compare key-value patterns
        for i, key1 in enumerate(all_keys):
            for key2 in all_keys[i+1:]:
                similarity = self._compare_key_patterns(all_key_values, key1, key2)
                
                if similarity > self.similarity_threshold:
                    similar_patterns.append({
                        'key1': key1,
                        'key2': key2,
                        'similarity': similarity,
                        'pattern_type': self._classify_pattern_similarity(key1, key2)
                    })
        
        return similar_patterns
    
    def _compare_key_patterns(self, all_key_values: Dict[str, Dict[str, List[str]]], 
                             key1: str, key2: str) -> float:
        """
        Compare patterns between two keys.
        
        Args:
            all_key_values: Key-value pairs from all files
            key1: First key
            key2: Second key
            
        Returns:
            Similarity score between 0 and 1
        """
        values1 = []
        values2 = []
        
        # Collect all values for both keys
        for file_key_values in all_key_values.values():
            if key1 in file_key_values:
                values1.extend(file_key_values[key1])
            if key2 in file_key_values:
                values2.extend(file_key_values[key2])
        
        if not values1 or not values2:
            return 0.0
        
        # Convert to TF-IDF vectors for comparison
        try:
            vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4))
            vectors = vectorizer.fit_transform([' '.join(values1), ' '.join(values2)])
            similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
            return float(similarity)
        except:
            # Fallback to simple string similarity
            return calculate_similarity(' '.join(values1), ' '.join(values2))
    
    def _classify_pattern_similarity(self, key1: str, key2: str) -> str:
        """
        Classify the type of pattern similarity between two keys.
        
        Args:
            key1: First key
            key2: Second key
            
        Returns:
            Pattern classification
        """
        # Extract key components
        parts1 = key1.split('.')
        parts2 = key2.split('.')
        
        if len(parts1) == len(parts2):
            # Check if they have similar structure
            if parts1[:-1] == parts2[:-1]:
                return "same_layer_different_field"
            elif parts1[-1] == parts2[-1]:
                return "same_field_different_layer"
        
        # Check for common prefixes
        if key1.startswith(key2) or key2.startswith(key1):
            return "hierarchical_relationship"
        
        return "similar_pattern"
    
    def _find_hidden_identifiers(self, all_key_values: Dict[str, Dict[str, List[str]]]) -> List[Dict[str, Any]]:
        """
        Find potential hidden identifiers across files.
        
        Args:
            all_key_values: Key-value pairs from all files
            
        Returns:
            List of potential hidden identifiers
        """
        hidden_identifiers = []
        
        # Look for values that appear consistently across files
        value_file_mapping = defaultdict(set)
        
        for file_path, file_key_values in all_key_values.items():
            for key, values in file_key_values.items():
                for value in values:
                    value_file_mapping[value].add(file_path)
        
        # Find values that appear in multiple files
        for value, files in value_file_mapping.items():
            if len(files) > 1:
                # Check if this value appears in the same context across files
                contexts = self._find_value_contexts(all_key_values, value)
                
                if len(contexts) > 1:
                    hidden_identifiers.append({
                        'value': value,
                        'files': list(files),
                        'contexts': contexts,
                        'confidence': len(files) / len(all_key_values)
                    })
        
        return hidden_identifiers
    
    def _find_value_contexts(self, all_key_values: Dict[str, Dict[str, List[str]]], 
                            target_value: str) -> List[str]:
        """
        Find the contexts (keys) where a value appears.
        
        Args:
            all_key_values: Key-value pairs from all files
            target_value: Value to find contexts for
            
        Returns:
            List of keys where the value appears
        """
        contexts = []
        
        for file_path, file_key_values in all_key_values.items():
            for key, values in file_key_values.items():
                if target_value in values:
                    contexts.append(key)
        
        return list(set(contexts))
    
    def _cluster_similar_values(self, all_key_values: Dict[str, Dict[str, List[str]]]) -> Dict[str, List[List[str]]]:
        """
        Cluster similar values together.
        
        Args:
            all_key_values: Key-value pairs from all files
            
        Returns:
            Dictionary mapping keys to clusters of similar values
        """
        value_clusters = {}
        
        for file_path, file_key_values in all_key_values.items():
            for key, values in file_key_values.items():
                if len(values) > 1:
                    # Create feature vectors for clustering
                    try:
                        vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4))
                        vectors = vectorizer.fit_transform(values)
                        
                        # Use DBSCAN for clustering
                        clustering = DBSCAN(eps=0.3, min_samples=2).fit(vectors)
                        
                        # Group values by cluster
                        clusters = defaultdict(list)
                        for i, label in enumerate(clustering.labels_):
                            if label != -1:  # Not noise
                                clusters[label].append(values[i])
                        
                        if clusters:
                            value_clusters[f"{file_path}:{key}"] = list(clusters.values())
                    except:
                        # Fallback: group by simple similarity
                        clusters = self._simple_value_clustering(values)
                        if clusters:
                            value_clusters[f"{file_path}:{key}"] = clusters
        
        return value_clusters
    
    def _simple_value_clustering(self, values: List[str]) -> List[List[str]]:
        """
        Simple clustering based on string similarity.
        
        Args:
            values: List of values to cluster
            
        Returns:
            List of value clusters
        """
        clusters = []
        used_indices = set()
        
        for i, value1 in enumerate(values):
            if i in used_indices:
                continue
            
            cluster = [value1]
            used_indices.add(i)
            
            for j, value2 in enumerate(values[i+1:], i+1):
                if j not in used_indices and calculate_similarity(value1, value2) > self.similarity_threshold:
                    cluster.append(value2)
                    used_indices.add(j)
            
            if len(cluster) > 1:
                clusters.append(cluster)
        
        return clusters
    
    def _calculate_pattern_statistics(self, all_key_values: Dict[str, Dict[str, List[str]]]) -> Dict[str, Any]:
        """
        Calculate statistics about the patterns found.
        
        Args:
            all_key_values: Key-value pairs from all files
            
        Returns:
            Dictionary containing pattern statistics
        """
        total_keys = 0
        total_values = 0
        unique_keys = set()
        unique_values = set()
        
        for file_key_values in all_key_values.values():
            for key, values in file_key_values.items():
                total_keys += 1
                unique_keys.add(key)
                total_values += len(values)
                unique_values.update(values)
        
        return {
            'total_keys': total_keys,
            'unique_keys': len(unique_keys),
            'total_values': total_values,
            'unique_values': len(unique_values),
            'average_values_per_key': total_values / total_keys if total_keys > 0 else 0,
            'files_analyzed': len(all_key_values)
        } 