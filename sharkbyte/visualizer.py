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
        
        # Common keys heatmap
        common_keys = pattern_results.get('common_keys', [])
        if common_keys:
            # Create a simple visualization of common keys
            plt.figure(figsize=(12, 6))
            key_lengths = [len(key) for key in common_keys]
            plt.bar(range(len(common_keys)), key_lengths)
            plt.title('Common Keys Found Across Files')
            plt.xlabel('Key Index')
            plt.ylabel('Key Length')
            plt.xticks(range(len(common_keys)), [f"Key {i+1}" for i in range(len(common_keys))])
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
                df = pd.DataFrame(pattern_stats)
                plt.figure(figsize=(12, 8))
                
                # Create subplots
                fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
                
                # Top plot: Total values vs Unique values
                ax1.scatter(df['total_values'], df['unique_values'], alpha=0.7)
                ax1.set_xlabel('Total Values')
                ax1.set_ylabel('Unique Values')
                ax1.set_title('Value Diversity Analysis')
                
                # Bottom plot: Diversity ratio
                ax2.bar(range(len(df)), df['diversity_ratio'])
                ax2.set_xlabel('Key Index')
                ax2.set_ylabel('Diversity Ratio (Unique/Total)')
                ax2.set_title('Value Diversity Ratio by Key')
                ax2.set_xticks(range(len(df)))
                ax2.set_xticklabels([f"Key {i+1}" for i in range(len(df))], rotation=45)
                
                plt.tight_layout()
                plt.savefig(f"{output_dir}/value_pattern_analysis.png", dpi=300, bbox_inches='tight')
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
                # Create a simple network visualization
                node_list = list(nodes)
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
                
                # Add edges
                fig.add_trace(go.Scatter(
                    x=edge_x, y=edge_y,
                    line=dict(width=0.5, color='#888'),
                    hoverinfo='none',
                    mode='lines'))
                
                # Add nodes
                fig.add_trace(go.Scatter(
                    x=[node_indices[node] for node in node_list],
                    y=[0] * len(node_list),
                    mode='markers+text',
                    marker=dict(size=20, color='lightblue'),
                    text=node_list,
                    textposition="bottom center",
                    hoverinfo='text'))
                
                fig.update_layout(
                    title='Similar Pattern Network',
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                
                fig.write_html(f"{output_dir}/similar_patterns_network.html")
        
        # Value pattern heatmap
        value_patterns = pattern_results.get('value_patterns', {})
        if value_patterns:
            # Create a heatmap of value patterns
            keys = list(value_patterns.keys())[:10]  # Limit to first 10 keys
            if keys:
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
                        x=['Total', 'Unique', 'Numeric', 'Hex', 'IP'],
                        y=keys,
                        colorscale='Viridis'))
                    
                    fig.update_layout(
                        title='Value Pattern Analysis Heatmap',
                        xaxis_title='Pattern Type',
                        yaxis_title='Keys')
                    
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
        
        # Add key findings
        common_keys = pattern_results.get('common_keys', [])
        hidden_identifiers = pattern_results.get('hidden_identifiers', [])
        similar_patterns = pattern_results.get('similar_patterns', [])
        
        html += f"""
            <li><strong>{len(common_keys)}</strong> common keys found across files</li>
            <li><strong>{len(hidden_identifiers)}</strong> potential hidden identifiers detected</li>
            <li><strong>{len(similar_patterns)}</strong> similar patterns identified</li>
        </ul>
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