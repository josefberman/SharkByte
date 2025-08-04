"""
Gradio GUI for SharkByte PCAP analyzer.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
import threading
import time
from dotenv import load_dotenv

# Try to import gradio, but handle the case where it's not available
try:
    import gradio as gr
    GRADIO_AVAILABLE = True
except ImportError:
    GRADIO_AVAILABLE = False
    gr = None  # Define gr as None to avoid NameError
    print("Warning: Gradio not available. GUI functionality will be disabled.")

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sharkbyte.analyzer import PCAPAnalyzer
from sharkbyte.pattern_detector import PatternDetector
from sharkbyte.llm_analyzer import LLMAnalyzer
from sharkbyte.visualizer import Visualizer
from sharkbyte.utils import find_pcap_files, save_results, load_results, ensure_event_loop


class SharkByteGUI:
    """
    Gradio GUI interface for SharkByte PCAP analyzer.
    """
    
    def __init__(self):
        self.analysis_results = {}
        self.pattern_results = {}
        self.llm_analysis = {}
        self.current_output_dir = None
        
    def analyze_pcap_files(self, 
                          pcap_folder: str,
                          openai_api_key: str,
                          model: str,
                          similarity_threshold: float,
                          max_patterns: int,
                          use_llm: bool,
                          generate_visualizations: bool,
                          progress=gr.Progress()) -> Dict[str, Any]:
        """
        Analyze PCAP files with progress updates.
        
        Args:
            pcap_folder: Path to folder containing PCAP files
            openai_api_key: OpenAI API key
            model: OpenAI model to use
            similarity_threshold: Threshold for pattern similarity
            max_patterns: Maximum patterns to analyze
            use_llm: Whether to use LLM analysis
            generate_visualizations: Whether to generate visualizations
            progress: Gradio progress tracker
            
        Returns:
            Dictionary containing analysis results and UI updates
        """
        try:
            # Handle async issues in threaded environment at the start
            ensure_event_loop()
            
            # Load environment variables from .env file
            load_dotenv()
            
            # Set OpenAI API key if provided (GUI input takes precedence over .env file)
            if openai_api_key and use_llm:
                os.environ["OPENAI_API_KEY"] = openai_api_key
            
            # Validate inputs
            if not pcap_folder or not os.path.exists(pcap_folder):
                return {
                    "status": "Error: PCAP folder does not exist",
                    "results": "",
                    "visualizations": None,
                    "html_report": None
                }
            
            progress(0.1, desc="Finding PCAP files...")
            
            # Step 1: Find PCAP files
            pcap_files = find_pcap_files(pcap_folder)
            if not pcap_files:
                return {
                    "status": "Error: No PCAP files found in the specified folder",
                    "results": "",
                    "visualizations": None,
                    "html_report": None
                }
            
            progress(0.2, desc=f"Found {len(pcap_files)} PCAP files")
            
            # Step 2: Analyze PCAP files
            progress(0.3, desc="Analyzing PCAP files...")
            try:
                analyzer = PCAPAnalyzer()
                self.analysis_results = analyzer.analyze_multiple_files(pcap_files)
            except RuntimeError as e:
                if "event loop" in str(e).lower():
                    print("⚠️  Async event loop issue detected during PCAP analysis.")
                    print("Retrying with event loop fix...")
                    ensure_event_loop()
                    analyzer = PCAPAnalyzer()
                    self.analysis_results = analyzer.analyze_multiple_files(pcap_files)
                else:
                    raise e
            
            progress(0.5, desc="Detecting patterns...")
            
            # Step 3: Detect patterns
            try:
                pattern_detector = PatternDetector(similarity_threshold=similarity_threshold)
                self.pattern_results = pattern_detector.detect_patterns(self.analysis_results)
            except RuntimeError as e:
                if "event loop" in str(e).lower():
                    print("⚠️  Async event loop issue detected during pattern detection.")
                    print("Retrying with event loop fix...")
                    ensure_event_loop()
                    pattern_detector = PatternDetector(similarity_threshold=similarity_threshold)
                    self.pattern_results = pattern_detector.detect_patterns(self.analysis_results)
                else:
                    raise e
            
            progress(0.7, desc="Running LLM analysis...")
            
            # Step 4: LLM Analysis (if enabled)
            self.llm_analysis = {}
            if use_llm and openai_api_key:
                try:
                    # Try to initialize LLM analyzer with better error handling
                    try:
                        llm_analyzer = LLMAnalyzer(model=model)
                        self.llm_analysis = llm_analyzer.analyze_patterns(self.pattern_results)
                    except RuntimeError as e:
                        if "event loop" in str(e).lower():
                            print("⚠️  Async event loop issue detected. Skipping LLM analysis.")
                            self.llm_analysis = {"error": "Async event loop issue - LLM analysis skipped"}
                        else:
                            raise e
                except Exception as e:
                    print(f"LLM Analysis error: {str(e)}")
                    self.llm_analysis = {"error": str(e)}
            
            progress(0.8, desc="Generating visualizations...")
            
            # Step 5: Generate visualizations (if requested)
            visualization_files = None
            if generate_visualizations:
                try:
                    # Create temporary directory for visualizations
                    self.current_output_dir = tempfile.mkdtemp(prefix="sharkbyte_")
                    visualizer = Visualizer()
                    visualizer.create_analysis_visualizations(
                        self.analysis_results, 
                        self.pattern_results, 
                        self.current_output_dir
                    )
                    
                    # Collect visualization files
                    viz_files = []
                    for file_path in Path(self.current_output_dir).glob("*"):
                        if file_path.is_file():
                            viz_files.append(str(file_path))
                    visualization_files = viz_files
                    
                except Exception as e:
                    print(f"Visualization error: {str(e)}")
            
            progress(0.9, desc="Generating HTML report...")
            
            # Step 6: Generate HTML report
            html_report = None
            if use_llm and openai_api_key and 'error' not in self.llm_analysis:
                try:
                    visualizer = Visualizer()
                    html_path = os.path.join(tempfile.gettempdir(), "sharkbyte_report.html")
                    visualizer.create_html_report(
                        self.analysis_results, 
                        self.pattern_results, 
                        self.llm_analysis,
                        html_path
                    )
                    html_report = html_path
                except Exception as e:
                    print(f"HTML report error: {str(e)}")
            
            progress(1.0, desc="Analysis complete!")
            
            # Generate results summary
            results_summary = self._generate_results_summary()
            
            return {
                "status": "Analysis completed successfully!",
                "results": results_summary,
                "visualizations": visualization_files,
                "html_report": html_report
            }
            
        except Exception as e:
            import traceback
            error_details = f"Error during analysis: {str(e)}\n\nTraceback:\n{traceback.format_exc()}"
            print(error_details)
            return {
                "status": f"Error during analysis: {str(e)}",
                "results": error_details,
                "visualizations": None,
                "html_report": None
            }
    
    def _generate_results_summary(self) -> str:
        """Generate a formatted summary of analysis results."""
        if not self.analysis_results or not self.pattern_results:
            return "No analysis results available."
        
        summary = []
        summary.append("=" * 60)
        summary.append("SHARKBYTE ANALYSIS RESULTS")
        summary.append("=" * 60)
        summary.append("")
        
        # Analysis statistics
        analysis_summary = self.analysis_results.get('summary', {})
        pattern_stats = self.pattern_results.get('statistics', {})
        
        summary.append("📊 ANALYSIS STATISTICS:")
        summary.append(f"  • Files analyzed: {analysis_summary.get('total_files', 0)}")
        summary.append(f"  • Total packets: {analysis_summary.get('total_packets', 0):,}")
        summary.append(f"  • Total size: {analysis_summary.get('total_size_mb', 0):.2f} MB")
        summary.append(f"  • Unique keys found: {pattern_stats.get('unique_keys', 0)}")
        summary.append("")
        
        # Key findings
        summary.append("🔍 KEY FINDINGS:")
        common_keys = self.pattern_results.get('common_keys', [])
        hidden_identifiers = self.pattern_results.get('hidden_identifiers', [])
        similar_patterns = self.pattern_results.get('similar_patterns', [])
        
        summary.append(f"  • Common keys across files: {len(common_keys)}")
        summary.append(f"  • Hidden identifiers detected: {len(hidden_identifiers)}")
        summary.append(f"  • Similar patterns found: {len(similar_patterns)}")
        summary.append("")
        
        # Common keys details
        if common_keys:
            summary.append("📋 COMMON KEYS FOUND:")
            for i, key in enumerate(common_keys[:10]):
                summary.append(f"  {i+1}. {key}")
            if len(common_keys) > 10:
                summary.append(f"  ... and {len(common_keys) - 10} more")
            summary.append("")
        
        # Hidden identifiers details
        if hidden_identifiers:
            summary.append("🕵️ HIDDEN IDENTIFIERS:")
            for i, identifier in enumerate(hidden_identifiers[:5]):
                value = identifier.get('value', 'N/A')
                files = len(identifier.get('files', []))
                confidence = identifier.get('confidence', 0)
                summary.append(f"  {i+1}. Value: {value}")
                summary.append(f"     Files: {files}, Confidence: {confidence:.2f}")
            if len(hidden_identifiers) > 5:
                summary.append(f"  ... and {len(hidden_identifiers) - 5} more")
            summary.append("")
        
        # LLM insights
        if self.llm_analysis and 'error' not in self.llm_analysis:
            llm_insights = self.llm_analysis.get('llm_insights', {})
            if llm_insights:
                summary.append("🤖 LLM INSIGHTS:")
                for insight_type, insight in list(llm_insights.items())[:3]:
                    summary.append(f"  • {insight_type.replace('_', ' ').title()}:")
                    # Truncate long insights
                    if len(insight) > 200:
                        insight = insight[:200] + "..."
                    summary.append(f"    {insight}")
                summary.append("")
        
        summary.append("=" * 60)
        return "\n".join(summary)
    
    def download_results(self) -> str:
        """Generate downloadable results file."""
        if not self.analysis_results:
            return None
        
        # Create results dictionary
        results = {
            "analysis_results": self.analysis_results,
            "pattern_results": self.pattern_results,
            "llm_analysis": self.llm_analysis,
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "files_analyzed": self.analysis_results.get('summary', {}).get('total_files', 0)
            }
        }
        
        # Save to temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(results, temp_file, indent=2, default=str)
        temp_file.close()
        
        return temp_file.name
    
    def cleanup_temp_files(self):
        """Clean up temporary files."""
        if self.current_output_dir and os.path.exists(self.current_output_dir):
            try:
                shutil.rmtree(self.current_output_dir)
            except:
                pass


def create_gui():
    """Create and launch the Gradio GUI."""
    
    if not GRADIO_AVAILABLE:
        raise ImportError("Gradio is not available. Please install it with: pip install gradio")
    
    gui = SharkByteGUI()
    
    with gr.Blocks(
        title="SharkByte - LLM-Powered PCAP Analyzer",
        theme=gr.themes.Soft(),
        css="""
        .gradio-container {
            max-width: 1200px !important;
        }
        .status-box {
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        """
    ) as interface:
        
        gr.Markdown("""
        # 🦈 SharkByte - LLM-Powered PCAP Analyzer
        
        Analyze Wireshark PCAP files to identify patterns and hidden identifiers across multiple files.
        """)
        
        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown("### 📁 Input Configuration")
                
                pcap_folder = gr.Textbox(
                    label="PCAP Folder Path",
                    placeholder="/path/to/pcap/files",
                    info="Path to folder containing PCAP files"
                )
                
                openai_api_key = gr.Textbox(
                    label="OpenAI API Key",
                    placeholder="sk-...",
                    type="password",
                    info="Required for LLM analysis (optional if disabled)"
                )
                
                with gr.Row():
                    model = gr.Dropdown(
                        choices=["gpt-4", "gpt-3.5-turbo"],
                        value="gpt-4",
                        label="OpenAI Model"
                    )
                    
                    similarity_threshold = gr.Slider(
                        minimum=0.1,
                        maximum=1.0,
                        value=0.8,
                        step=0.1,
                        label="Similarity Threshold"
                    )
                
                max_patterns = gr.Number(
                    value=100,
                    label="Max Patterns",
                    info="Maximum number of patterns to analyze"
                )
                
                with gr.Row():
                    use_llm = gr.Checkbox(
                        value=True,
                        label="Enable LLM Analysis"
                    )
                    
                    generate_visualizations = gr.Checkbox(
                        value=True,
                        label="Generate Visualizations"
                    )
                
                analyze_btn = gr.Button(
                    "🚀 Start Analysis",
                    variant="primary",
                    size="lg"
                )
            
            with gr.Column(scale=2):
                gr.Markdown("### 📊 Analysis Results")
                
                status_output = gr.Textbox(
                    label="Status",
                    interactive=False,
                    lines=2
                )
                
                results_output = gr.Textbox(
                    label="Results Summary",
                    interactive=False,
                    lines=20,
                    max_lines=30
                )
                
                with gr.Row():
                    download_btn = gr.Button(
                        "📥 Download Results (JSON)",
                        variant="secondary"
                    )
                    
                    download_results = gr.File(
                        label="Download Results",
                        visible=False
                    )
                
                with gr.Row():
                    viz_gallery = gr.Gallery(
                        label="Visualizations",
                        show_label=True,
                        visible=False
                    )
                    
                    html_report = gr.File(
                        label="HTML Report",
                        visible=False
                    )
        
        # Event handlers
        def on_analyze(pcap_folder, api_key, model, similarity, max_pat, use_llm, gen_viz):
            result = gui.analyze_pcap_files(
                pcap_folder=pcap_folder,
                openai_api_key=api_key,
                model=model,
                similarity_threshold=similarity,
                max_patterns=max_pat,
                use_llm=use_llm,
                generate_visualizations=gen_viz
            )
            
            # Update outputs
            status_class = "success" if "completed successfully" in result["status"] else "error"
            
            return (
                result["status"],
                result["results"],
                gr.File(visible=True, value=gui.download_results()) if "completed successfully" in result["status"] else gr.File(visible=False),
                gr.Gallery(visible=bool(result["visualizations"]), value=result["visualizations"]) if result["visualizations"] else gr.Gallery(visible=False),
                gr.File(visible=bool(result["html_report"]), value=result["html_report"]) if result["html_report"] else gr.File(visible=False)
            )
        
        def on_download():
            if gui.analysis_results:
                return gr.File(visible=True, value=gui.download_results())
            return gr.File(visible=False)
        
        # Connect events
        analyze_btn.click(
            fn=on_analyze,
            inputs=[pcap_folder, openai_api_key, model, similarity_threshold, max_patterns, use_llm, generate_visualizations],
            outputs=[status_output, results_output, download_results, viz_gallery, html_report]
        )
        
        download_btn.click(
            fn=on_download,
            outputs=[download_results]
        )
        
        # Add examples
        gr.Examples(
            examples=[
                ["/path/to/pcap/files", "your-api-key-here", "gpt-4", 0.8, 100, True, True],
                ["/home/user/captures", "", "gpt-4", 0.7, 50, False, True],
            ],
            inputs=[pcap_folder, openai_api_key, model, similarity_threshold, max_patterns, use_llm, generate_visualizations],
            label="Example Configurations"
        )
        
        gr.Markdown("""
        ### 📖 How to Use
        
        1. **Enter the path** to your PCAP files folder
        2. **Optional**: Enter your OpenAI API key for LLM analysis
        3. **Configure settings** like similarity threshold and model
        4. **Click "Start Analysis"** to begin processing
        5. **Download results** and view visualizations
        
        ### 🔍 What SharkByte Finds
        
        - **Common Keys**: Keys that appear across multiple PCAP files
        - **Hidden Identifiers**: Values that appear consistently (user IDs, session tokens)
        - **Similar Patterns**: Keys with similar value distributions
        - **Value Clusters**: Groups of similar values indicating related activity
        
        ### 📊 Output
        
        - **JSON Results**: Detailed analysis data
        - **Visualizations**: Charts and graphs of findings
        - **HTML Report**: Comprehensive report with LLM insights
        """)
    
    return interface


def launch_gui(server_name="0.0.0.0", server_port=7860, share=False):
    """
    Launch the SharkByte GUI.
    
    Args:
        server_name: Server hostname
        server_port: Server port
        share: Whether to create a public link
    """
    if not GRADIO_AVAILABLE:
        print("❌ Gradio is not available. Please install it with:")
        print("   pip install gradio")
        print("\nAlternatively, you can use the command-line interface:")
        print("   python main.py --pcap-folder /path/to/pcaps --output results.json")
        return
    
    interface = create_gui()
    
    print("🚀 Launching SharkByte GUI...")
    print(f"📱 Access the interface at: http://{server_name}:{server_port}")
    if share:
        print("🌐 Public link will be generated")
    
    interface.launch(
        server_name=server_name,
        server_port=server_port,
        share=share,
        show_error=True
    )


if __name__ == "__main__":
    launch_gui() 