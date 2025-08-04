"""
Visualization tools for SharkByte PCAP analyzer.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
import json
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import re


class Visualizer:
    """
    Generates visualizations for PCAP analysis results.
    """
    
    def __init__(self):
        self.setup_plotting_style()
        
    def setup_plotting_style(self):
        """Setup matplotlib and seaborn plotting styles."""
        plt.style.use('default')
        sns.set_palette("husl")
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 10
    
    def _truncate_text(self, text: str, max_length: int = 30) -> str:
        """
        Truncate text to a maximum length with ellipsis.
        
        Args:
            text: Text to truncate
            max_length: Maximum length before truncation
            
        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    def _format_key_name(self, key: str) -> str:
        """
        Format key names for better visualization.
        
        Args:
            key: Original key name
            
        Returns:
            Formatted key name
        """
        # Remove common prefixes
        key = re.sub(r'^[a-z]+\.[a-z]+\.', '', key)
        
        # Replace underscores and dots with spaces
        key = key.replace('_', ' ').replace('.', ' ')
        
        # Capitalize words
        key = ' '.join(word.capitalize() for word in key.split())
        
        # Truncate if still too long
        return self._truncate_text(key, 25)
    
    def _format_value(self, value: str) -> str:
        """
        Format values for better visualization.
        
        Args:
            value: Original value
            
        Returns:
            Formatted value
        """
        # Handle different value types
        if not value or value == "null":
            return "N/A"
        
        # Truncate long values
        if len(value) > 20:
            return self._truncate_text(value, 20)
        
        return value
    
    def _create_key_mapping(self, keys: List[str]) -> Dict[str, str]:
        """
        Create a mapping from original keys to display names.
        
        Args:
            keys: List of original keys
            
        Returns:
            Dictionary mapping original keys to display names
        """
        mapping = {}
        for i, key in enumerate(keys):
            display_name = self._format_key_name(key)
            # If display name is not unique, add index
            if display_name in mapping.values():
                display_name = f"{display_name} ({i+1})"
            mapping[key] = display_name
        return mapping
        
    def create_analysis_visualizations(self, analysis_results: Dict[str, Any], 
                                     pattern_results: Dict[str, Any],
                                     output_dir: str = "visualizations"):
        """
        Create comprehensive visualizations for the analysis results.
        
        Args:
            analysis_results: Results from PCAPAnalyzer
            pattern_results: Results from PatternDetector
            output_dir: Directory to save visualizations
        """
        Path(output_dir).mkdir(exist_ok=True)
        
        print("Creating visualizations...")
        
        # Create various visualizations
        self._create_summary_charts(analysis_results, output_dir)
        self._create_pattern_visualizations(pattern_results, output_dir)
        self._create_network_visualizations(analysis_results, output_dir)
        self._create_interactive_plots(pattern_results, output_dir)
        
        print(f"Visualizations saved to {output_dir}/")
    
    def _create_summary_charts(self, analysis_results: Dict[str, Any], output_dir: str):
        """Create summary charts for the analysis."""
        
        # Protocol distribution
        protocols = analysis_results.get('summary', {}).get('common_protocols', {})
        if protocols:
            plt.figure(figsize=(12, 6))
            protocols_df = pd.DataFrame(list(protocols.items()), columns=['Protocol', 'Count'])
            protocols_df = protocols_df.sort_values('Count', ascending=False).head(10)
            
            sns.barplot(data=protocols_df, x='Count', y='Protocol')
            plt.title('Top 10 Protocols by Packet Count')
            plt.xlabel('Packet Count')
            plt.ylabel('Protocol')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/protocol_distribution.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # File size distribution
        file_sizes = []
        file_names = []
        for file_path, file_results in analysis_results.get('files', {}).items():
            if 'error' not in file_results:
                file_sizes.append(file_results.get('file_size_mb', 0))
                file_names.append(Path(file_path).name)
        
        if file_sizes:
            plt.figure(figsize=(12, 6))
            plt.bar(range(len(file_sizes)), file_sizes)
            plt.title('PCAP File Size Distribution')
            plt.xlabel('Files')
            plt.ylabel('Size (MB)')
            plt.xticks(range(len(file_names)), file_names, rotation=45, ha='right')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/file_size_distribution.png", dpi=300, bbox_inches='tight')
            plt.close()
    
    def _create_pattern_visualizations(self, pattern_results: Dict[str, Any], output_dir: str):
        """Create visualizations for pattern analysis."""
        
        # Common keys visualization
        common_keys = pattern_results.get('common_keys', [])
        if common_keys:
            # Create a better visualization of common keys
            key_mapping = self._create_key_mapping(common_keys[:15])  # Limit to top 15 keys
            display_names = list(key_mapping.values())
            
            plt.figure(figsize=(14, 8))
            y_pos = np.arange(len(display_names))
            
            # Create horizontal bar chart for better readability
            plt.barh(y_pos, [1] * len(display_names), color='skyblue', alpha=0.7)
            plt.yticks(y_pos, display_names)
            plt.xlabel('Presence')
            plt.title('Common Keys Found Across Files', fontsize=14, fontweight='bold')
            plt.gca().invert_yaxis()  # Invert to show most important at top
            
            # Add count annotations
            for i, (original_key, display_name) in enumerate(key_mapping.items()):
                plt.text(0.5, i, f"'{original_key}'", 
                        ha='center', va='center', fontsize=8, alpha=0.7)
            
            plt.tight_layout()
            plt.savefig(f"{output_dir}/common_keys_analysis.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Value pattern analysis
        value_patterns = pattern_results.get('value_patterns', {})
        if value_patterns:
            # Create a summary of value patterns
            pattern_stats = []
            for key, pattern_info in value_patterns.items():
                pattern_stats.append({
                    'key': key,
                    'total_values': pattern_info.get('total_values', 0),
                    'unique_values': pattern_info.get('unique_values', 0),
                    'diversity_ratio': pattern_info.get('unique_values', 0) / max(pattern_info.get('total_values', 1), 1)
                })
            
            if pattern_stats:
                # Sort by total values and take top 10
                pattern_stats.sort(key=lambda x: x['total_values'], reverse=True)
                top_patterns = pattern_stats[:10]
                
                df = pd.DataFrame(top_patterns)
                key_mapping = self._create_key_mapping(df['key'].tolist())
                df['display_name'] = df['key'].map(key_mapping)
                
                # Create subplots with better formatting
                fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 12))
                
                # Top plot: Total values vs Unique values
                scatter = ax1.scatter(df['total_values'], df['unique_values'], 
                                    alpha=0.7, s=100, c=df['diversity_ratio'], cmap='viridis')
                ax1.set_xlabel('Total Values', fontsize=12)
                ax1.set_ylabel('Unique Values', fontsize=12)
                ax1.set_title('Value Diversity Analysis', fontsize=14, fontweight='bold')
                
                # Add colorbar
                cbar = plt.colorbar(scatter, ax=ax1)
                cbar.set_label('Diversity Ratio', fontsize=10)
                
                # Add annotations for key points
                for i, row in df.iterrows():
                    if row['total_values'] > df['total_values'].quantile(0.75):
                        ax1.annotate(row['display_name'], 
                                   (row['total_values'], row['unique_values']),
                                   xytext=(5, 5), textcoords='offset points',
                                   fontsize=8, alpha=0.8)
                
                # Bottom plot: Diversity ratio with formatted labels
                bars = ax2.bar(range(len(df)), df['diversity_ratio'], 
                              color='lightcoral', alpha=0.7)
                ax2.set_xlabel('Keys', fontsize=12)
                ax2.set_ylabel('Diversity Ratio (Unique/Total)', fontsize=12)
                ax2.set_title('Value Diversity Ratio by Key', fontsize=14, fontweight='bold')
                ax2.set_xticks(range(len(df)))
                ax2.set_xticklabels(df['display_name'], rotation=45, ha='right', fontsize=10)
                
                # Add value labels on bars
                for i, bar in enumerate(bars):
                    height = bar.get_height()
                    ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                            f'{height:.2f}', ha='center', va='bottom', fontsize=8)
                
                plt.tight_layout()
                plt.savefig(f"{output_dir}/value_pattern_analysis.png", dpi=300, bbox_inches='tight')
                plt.close()
                
        # Hidden identifiers visualization
        hidden_identifiers = pattern_results.get('hidden_identifiers', [])
        if hidden_identifiers:
            # Create a visualization of hidden identifiers
            plt.figure(figsize=(14, 8))
            
            # Sort by confidence and take top 10
            sorted_identifiers = sorted(hidden_identifiers, 
                                       key=lambda x: x.get('confidence', 0), reverse=True)[:10]
            
            identifiers = []
            confidences = []
            display_values = []
            
            for identifier in sorted_identifiers:
                value = identifier.get('value', 'N/A')
                confidence = identifier.get('confidence', 0)
                files_count = len(identifier.get('files', []))
                
                identifiers.append(f"ID {len(identifiers)+1}")
                confidences.append(confidence)
                display_values.append(self._format_value(value))
            
            # Create horizontal bar chart
            y_pos = np.arange(len(identifiers))
            bars = plt.barh(y_pos, confidences, color='gold', alpha=0.7)
            
            plt.yticks(y_pos, identifiers)
            plt.xlabel('Confidence Score', fontsize=12)
            plt.title('Hidden Identifiers by Confidence', fontsize=14, fontweight='bold')
            plt.gca().invert_yaxis()
            
            # Add value annotations
            for i, (bar, value) in enumerate(zip(bars, display_values)):
                width = bar.get_width()
                plt.text(width + 0.01, bar.get_y() + bar.get_height()/2,
                        f"'{value}'", ha='left', va='center', fontsize=9, alpha=0.8)
            
            plt.tight_layout()
            plt.savefig(f"{output_dir}/hidden_identifiers.png", dpi=300, bbox_inches='tight')
            plt.close()
    
    def _create_network_visualizations(self, analysis_results: Dict[str, Any], output_dir: str):
        """Create network-specific visualizations."""
        
        # IP address analysis
        all_ips = analysis_results.get('summary', {}).get('all_ip_addresses', [])
        if all_ips:
            # Analyze IP address patterns
            ip_octets = []
            for ip in all_ips:
                try:
                    octets = ip.split('.')
                    if len(octets) == 4:
                        ip_octets.append([int(octet) for octet in octets])
                except:
                    continue
            
            if ip_octets:
                df = pd.DataFrame(ip_octets, columns=['Octet1', 'Octet2', 'Octet3', 'Octet4'])
                
                plt.figure(figsize=(15, 10))
                
                # Create subplots for each octet
                fig, axes = plt.subplots(2, 2, figsize=(15, 10))
                axes = axes.ravel()
                
                for i, octet in enumerate(['Octet1', 'Octet2', 'Octet3', 'Octet4']):
                    axes[i].hist(df[octet], bins=20, alpha=0.7, edgecolor='black')
                    axes[i].set_title(f'{octet} Distribution')
                    axes[i].set_xlabel('Value')
                    axes[i].set_ylabel('Frequency')
                
                plt.tight_layout()
                plt.savefig(f"{output_dir}/ip_address_analysis.png", dpi=300, bbox_inches='tight')
                plt.close()
        
        # Port analysis
        all_ports = analysis_results.get('summary', {}).get('all_ports', [])
        if all_ports:
            try:
                port_numbers = [int(port) for port in all_ports if port.isdigit()]
                if port_numbers:
                    plt.figure(figsize=(12, 6))
                    plt.hist(port_numbers, bins=50, alpha=0.7, edgecolor='black')
                    plt.title('Port Number Distribution')
                    plt.xlabel('Port Number')
                    plt.ylabel('Frequency')
                    plt.tight_layout()
                    plt.savefig(f"{output_dir}/port_distribution.png", dpi=300, bbox_inches='tight')
                    plt.close()
            except:
                pass
    
    def _create_interactive_plots(self, pattern_results: Dict[str, Any], output_dir: str):
        """Create interactive Plotly visualizations."""
        
        # Similar patterns network graph
        similar_patterns = pattern_results.get('similar_patterns', [])
        if similar_patterns:
            # Create a network graph of similar patterns
            nodes = set()
            edges = []
            
            for pattern in similar_patterns:
                key1 = pattern.get('key1', '')
                key2 = pattern.get('key2', '')
                similarity = pattern.get('similarity', 0)
                
                nodes.add(key1)
                nodes.add(key2)
                edges.append((key1, key2, similarity))
            
            if nodes and edges:
                # Create formatted node names
                node_list = list(nodes)
                key_mapping = self._create_key_mapping(node_list)
                display_names = [key_mapping[node] for node in node_list]
                node_indices = {node: i for i, node in enumerate(node_list)}
                
                # Create edge traces
                edge_x = []
                edge_y = []
                edge_text = []
                
                for edge in edges:
                    x0, y0 = node_indices[edge[0]], 0
                    x1, y1 = node_indices[edge[1]], 1
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
                    edge_text.append(f"Similarity: {edge[2]:.3f}")
                
                # Create the network plot
                fig = go.Figure()
                
                # Add edges with hover information
                fig.add_trace(go.Scatter(
                    x=edge_x, y=edge_y,
                    line=dict(width=2, color='#888'),
                    hoverinfo='text',
                    hovertext=edge_text,
                    mode='lines'))
                
                # Add nodes with formatted labels
                fig.add_trace(go.Scatter(
                    x=[node_indices[node] for node in node_list],
                    y=[0] * len(node_list),
                    mode='markers+text',
                    marker=dict(size=25, color='lightblue', line=dict(width=2, color='darkblue')),
                    text=display_names,
                    textposition="bottom center",
                    hoverinfo='text',
                    hovertext=[f"Original: {node}" for node in node_list]))
                
                fig.update_layout(
                    title='Similar Pattern Network',
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=50,l=5,r=5,t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    plot_bgcolor='white')
                
                fig.write_html(f"{output_dir}/similar_patterns_network.html")
        
        # Value pattern heatmap
        value_patterns = pattern_results.get('value_patterns', {})
        if value_patterns:
            # Create a heatmap of value patterns
            keys = list(value_patterns.keys())[:10]  # Limit to first 10 keys
            if keys:
                # Create formatted key names
                key_mapping = self._create_key_mapping(keys)
                display_names = [key_mapping[key] for key in keys]
                
                # Create a matrix of value counts
                pattern_matrix = []
                for key in keys:
                    pattern_info = value_patterns[key]
                    row = [
                        pattern_info.get('total_values', 0),
                        pattern_info.get('unique_values', 0),
                        len(pattern_info.get('patterns', {}).get('numeric_patterns', [])),
                        len(pattern_info.get('patterns', {}).get('hex_patterns', [])),
                        len(pattern_info.get('patterns', {}).get('ip_patterns', []))
                    ]
                    pattern_matrix.append(row)
                
                if pattern_matrix:
                    fig = go.Figure(data=go.Heatmap(
                        z=pattern_matrix,
                        x=['Total Values', 'Unique Values', 'Numeric Patterns', 'Hex Patterns', 'IP Patterns'],
                        y=display_names,
                        colorscale='Viridis',
                        hoverongaps=False))
                    
                    # Add hover text with original key names
                    hover_text = []
                    for i, key in enumerate(keys):
                        row = []
                        for j, col in enumerate(['Total', 'Unique', 'Numeric', 'Hex', 'IP']):
                            value = pattern_matrix[i][j]
                            row.append(f"Key: {key}<br>{col}: {value}")
                        hover_text.append(row)
                    
                    fig.update_traces(hovertemplate='%{text}<extra></extra>', text=hover_text)
                    
                    fig.update_layout(
                        title='Value Pattern Analysis Heatmap',
                        xaxis_title='Pattern Type',
                        yaxis_title='Keys',
                        height=600,
                        margin=dict(l=200, r=50, t=50, b=50))
                    
                    fig.write_html(f"{output_dir}/value_pattern_heatmap.html")
    
    def create_html_report(self, analysis_results: Dict[str, Any], 
                          pattern_results: Dict[str, Any],
                          llm_analysis: Dict[str, Any],
                          output_path: str = "sharkbyte_report.html"):
        """
        Create an HTML report with all analysis results and visualizations.
        
        Args:
            analysis_results: PCAP analysis results
            pattern_results: Pattern detection results
            llm_analysis: LLM analysis results
            output_path: Path to save the HTML report
        """
        html_content = self._generate_html_content(analysis_results, pattern_results, llm_analysis)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report saved to {output_path}")
    
    def _generate_html_content(self, analysis_results: Dict[str, Any],
                             pattern_results: Dict[str, Any],
                             llm_analysis: Dict[str, Any]) -> str:
        """Generate HTML content for the report."""
        
        stats = analysis_results.get('summary', {})
        pattern_stats = pattern_results.get('statistics', {})
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SharkByte PCAP Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .stat-box {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #666; }}
        .insight {{ background-color: #e8f4fd; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }}
        .warning {{ background-color: #fff3cd; padding: 15px; margin: 10px 0; border-left: 4px solid #ffc107; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SharkByte PCAP Analysis Report</h1>
        <p>LLM-Powered Network Traffic Analysis</p>
    </div>
    
    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{stats.get('total_files', 0)}</div>
                <div class="stat-label">Files Analyzed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{stats.get('total_packets', 0):,}</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{pattern_stats.get('unique_keys', 0)}</div>
                <div class="stat-label">Unique Keys</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(pattern_results.get('hidden_identifiers', []))}</div>
                <div class="stat-label">Hidden Identifiers</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>LLM Analysis Insights</h2>
"""
        
        # Add LLM insights
        llm_insights = llm_analysis.get('llm_insights', {})
        for insight_type, insight in llm_insights.items():
            html += f"""
        <div class="insight">
            <h3>{insight_type.replace('_', ' ').title()}</h3>
            <p>{insight.replace(chr(10), '<br>')}</p>
        </div>
"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>Key Findings</h2>
        <ul>
"""
        
        # Add key findings with formatted display
        common_keys = pattern_results.get('common_keys', [])
        hidden_identifiers = pattern_results.get('hidden_identifiers', [])
        similar_patterns = pattern_results.get('similar_patterns', [])
        
        html += f"""
            <li><strong>{len(common_keys)}</strong> common keys found across files</li>
            <li><strong>{len(hidden_identifiers)}</strong> potential hidden identifiers detected</li>
            <li><strong>{len(similar_patterns)}</strong> similar patterns identified</li>
        </ul>
        
        <h3>Top Common Keys</h3>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
"""
        
        # Add formatted common keys
        if common_keys:
            key_mapping = self._create_key_mapping(common_keys[:10])  # Top 10 keys
            for i, (original_key, display_name) in enumerate(key_mapping.items()):
                html += f"""
            <div style="margin: 5px 0; padding: 5px; border-left: 3px solid #3498db;">
                <strong>{display_name}</strong><br>
                <small style="color: #666;">Original: {self._truncate_text(original_key, 50)}</small>
            </div>
"""
        
        html += """
        </div>
        
        <h3>Top Hidden Identifiers</h3>
        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0;">
"""
        
        # Add formatted hidden identifiers
        if hidden_identifiers:
            sorted_identifiers = sorted(hidden_identifiers, 
                                       key=lambda x: x.get('confidence', 0), reverse=True)[:5]
            for i, identifier in enumerate(sorted_identifiers):
                value = identifier.get('value', 'N/A')
                confidence = identifier.get('confidence', 0)
                files_count = len(identifier.get('files', []))
                
                html += f"""
            <div style="margin: 5px 0; padding: 5px; border-left: 3px solid #ffc107;">
                <strong>ID {i+1}</strong> (Confidence: {confidence:.2f})<br>
                <small style="color: #666;">Value: {self._format_value(value)} | Files: {files_count}</small>
            </div>
"""
        
        html += """
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div class="warning">
            <h3>Next Steps</h3>
            <ul>
                <li>Investigate hidden identifiers for potential security implications</li>
                <li>Monitor similar patterns for network behavior analysis</li>
                <li>Use common keys for traffic classification and filtering</li>
                <li>Consider implementing pattern-based detection rules</li>
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h2>Generated Visualizations</h2>
        <p>Check the 'visualizations' directory for detailed charts and graphs.</p>
    </div>
</body>
</html>
"""
        
        return html 