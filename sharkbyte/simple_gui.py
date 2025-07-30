"""
Simple Tkinter GUI for SharkByte PCAP analyzer.
Alternative to Gradio for users with audio dependency issues.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import json
import tempfile
import threading
from pathlib import Path
from typing import Dict, Any
import time

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sharkbyte.analyzer import PCAPAnalyzer
from sharkbyte.pattern_detector import PatternDetector
from sharkbyte.llm_analyzer import LLMAnalyzer
from sharkbyte.visualizer import Visualizer
from sharkbyte.utils import find_pcap_files, save_results


class SharkByteSimpleGUI:
    """
    Simple Tkinter GUI for SharkByte PCAP analyzer.
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SharkByte - LLM-Powered PCAP Analyzer")
        self.root.geometry("800x600")
        
        self.analysis_results = {}
        self.pattern_results = {}
        self.llm_analysis = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface."""
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🦈 SharkByte PCAP Analyzer", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input Configuration", padding="10")
        input_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        # PCAP folder selection
        ttk.Label(input_frame, text="PCAP Folder:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pcap_folder_var = tk.StringVar()
        pcap_entry = ttk.Entry(input_frame, textvariable=self.pcap_folder_var, width=50)
        pcap_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 5), pady=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_folder).grid(row=0, column=2, pady=5)
        
        # OpenAI API Key
        ttk.Label(input_frame, text="OpenAI API Key:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.api_key_var = tk.StringVar()
        api_entry = ttk.Entry(input_frame, textvariable=self.api_key_var, show="*", width=50)
        api_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 5), pady=5)
        
        # Analysis options
        options_frame = ttk.LabelFrame(main_frame, text="Analysis Options", padding="10")
        options_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        options_frame.columnconfigure(1, weight=1)
        
        # Model selection
        ttk.Label(options_frame, text="OpenAI Model:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.model_var = tk.StringVar(value="gpt-4")
        model_combo = ttk.Combobox(options_frame, textvariable=self.model_var, 
                                  values=["gpt-4", "gpt-3.5-turbo"], state="readonly")
        model_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=5)
        
        # Similarity threshold
        ttk.Label(options_frame, text="Similarity Threshold:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.similarity_var = tk.DoubleVar(value=0.8)
        similarity_scale = ttk.Scale(options_frame, from_=0.1, to=1.0, variable=self.similarity_var, 
                                   orient=tk.HORIZONTAL)
        similarity_scale.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=5)
        ttk.Label(options_frame, textvariable=tk.StringVar(value="0.8")).grid(row=1, column=2, pady=5)
        
        # Checkboxes
        self.use_llm_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable LLM Analysis", 
                       variable=self.use_llm_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.gen_viz_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Generate Visualizations", 
                       variable=self.gen_viz_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Analysis button
        self.analyze_btn = ttk.Button(main_frame, text="🚀 Start Analysis", 
                                     command=self.start_analysis, style="Accent.TButton")
        self.analyze_btn.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.progress_var).grid(row=4, column=0, columnspan=2, pady=5)
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="10")
        results_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        self.save_btn = ttk.Button(buttons_frame, text="💾 Save Results", 
                                  command=self.save_results, state="disabled")
        self.save_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.open_viz_btn = ttk.Button(buttons_frame, text="📊 Open Visualizations", 
                                      command=self.open_visualizations, state="disabled")
        self.open_viz_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(buttons_frame, text="❌ Exit", command=self.root.quit).pack(side=tk.LEFT)
        
    def browse_folder(self):
        """Browse for PCAP folder."""
        folder = filedialog.askdirectory(title="Select PCAP Files Folder")
        if folder:
            self.pcap_folder_var.set(folder)
    
    def start_analysis(self):
        """Start the analysis in a separate thread."""
        if not self.pcap_folder_var.get():
            messagebox.showerror("Error", "Please select a PCAP folder")
            return
        
        # Disable button and start progress
        self.analyze_btn.config(state="disabled")
        self.progress_bar.start()
        self.progress_var.set("Starting analysis...")
        
        # Start analysis in separate thread
        thread = threading.Thread(target=self.run_analysis)
        thread.daemon = True
        thread.start()
    
    def run_analysis(self):
        """Run the analysis."""
        try:
            # Set OpenAI API key if provided
            if self.api_key_var.get() and self.use_llm_var.get():
                os.environ["OPENAI_API_KEY"] = self.api_key_var.get()
            
            # Find PCAP files
            self.update_progress("Finding PCAP files...")
            pcap_files = find_pcap_files(self.pcap_folder_var.get())
            
            if not pcap_files:
                self.show_error("No PCAP files found in the specified folder")
                return
            
            self.update_progress(f"Found {len(pcap_files)} PCAP files")
            
            # Analyze PCAP files
            self.update_progress("Analyzing PCAP files...")
            analyzer = PCAPAnalyzer()
            self.analysis_results = analyzer.analyze_multiple_files(pcap_files)
            
            # Detect patterns
            self.update_progress("Detecting patterns...")
            pattern_detector = PatternDetector(similarity_threshold=self.similarity_var.get())
            self.pattern_results = pattern_detector.detect_patterns(self.analysis_results)
            
            # LLM Analysis
            if self.use_llm_var.get():
                self.update_progress("Running LLM analysis...")
                try:
                    llm_analyzer = LLMAnalyzer(model=self.model_var.get())
                    self.llm_analysis = llm_analyzer.analyze_patterns(self.pattern_results)
                except Exception as e:
                    self.llm_analysis = {"error": str(e)}
            
            # Generate visualizations
            if self.gen_viz_var.get():
                self.update_progress("Generating visualizations...")
                try:
                    viz_dir = "sharkbyte_visualizations"
                    visualizer = Visualizer()
                    visualizer.create_analysis_visualizations(
                        self.analysis_results, 
                        self.pattern_results, 
                        viz_dir
                    )
                    self.viz_dir = viz_dir
                except Exception as e:
                    print(f"Visualization error: {str(e)}")
            
            # Generate results summary
            self.update_progress("Generating results summary...")
            results_summary = self.generate_results_summary()
            
            # Update UI
            self.root.after(0, self.analysis_complete, results_summary)
            
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
    
    def update_progress(self, message):
        """Update progress message."""
        self.root.after(0, lambda: self.progress_var.set(message))
    
    def analysis_complete(self, results_summary):
        """Called when analysis is complete."""
        self.progress_bar.stop()
        self.progress_var.set("Analysis complete!")
        self.analyze_btn.config(state="normal")
        
        # Update results text
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results_summary)
        
        # Enable buttons
        self.save_btn.config(state="normal")
        if hasattr(self, 'viz_dir'):
            self.open_viz_btn.config(state="normal")
        
        messagebox.showinfo("Success", "Analysis completed successfully!")
    
    def show_error(self, message):
        """Show error message."""
        self.progress_bar.stop()
        self.progress_var.set("Error occurred")
        self.analyze_btn.config(state="normal")
        messagebox.showerror("Error", message)
    
    def generate_results_summary(self):
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
    
    def save_results(self):
        """Save results to file."""
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                results = {
                    "analysis_results": self.analysis_results,
                    "pattern_results": self.pattern_results,
                    "llm_analysis": self.llm_analysis,
                    "metadata": {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "files_analyzed": self.analysis_results.get('summary', {}).get('total_files', 0)
                    }
                }
                
                save_results(results, filename)
                messagebox.showinfo("Success", f"Results saved to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")
    
    def open_visualizations(self):
        """Open visualizations folder."""
        if hasattr(self, 'viz_dir') and os.path.exists(self.viz_dir):
            import subprocess
            import platform
            
            try:
                if platform.system() == "Windows":
                    os.startfile(self.viz_dir)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["open", self.viz_dir])
                else:  # Linux
                    subprocess.run(["xdg-open", self.viz_dir])
            except Exception as e:
                messagebox.showinfo("Info", f"Visualizations saved to: {os.path.abspath(self.viz_dir)}")
        else:
            messagebox.showwarning("Warning", "No visualizations available")
    
    def run(self):
        """Run the GUI."""
        self.root.mainloop()


def launch_simple_gui():
    """Launch the simple Tkinter GUI."""
    app = SharkByteSimpleGUI()
    app.run()


if __name__ == "__main__":
    launch_simple_gui() 