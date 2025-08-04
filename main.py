#!/usr/bin/env python3
"""
SharkByte - LLM-Powered PCAP Analyzer

Main entry point for analyzing PCAP files to identify patterns and hidden identifiers.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from .env file
load_dotenv()

from sharkbyte.analyzer import PCAPAnalyzer
from sharkbyte.pattern_detector import PatternDetector
from sharkbyte.llm_analyzer import LLMAnalyzer
from sharkbyte.visualizer import Visualizer
from sharkbyte.utils import find_pcap_files, save_results, load_results


def main():
    """Main entry point for SharkByte."""
    parser = argparse.ArgumentParser(
        description="SharkByte - LLM-Powered PCAP Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --pcap-folder /path/to/pcaps --output results.json
  python main.py --pcap-folder /path/to/pcaps --output results.json --model gpt-4 --similarity-threshold 0.8
  python main.py --pcap-folder /path/to/pcaps --output results.json --no-llm --visualize
        """
    )
    
    parser.add_argument(
        "--pcap-folder",
        required=False,
        help="Path to folder containing PCAP files (not required for GUI modes)"
    )
    
    parser.add_argument(
        "--output",
        default="sharkbyte_results.json",
        help="Output file for results (default: sharkbyte_results.json)"
    )
    
    parser.add_argument(
        "--model",
        default="gpt-4",
        help="OpenAI model to use for LLM analysis (default: gpt-4)"
    )
    
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.8,
        help="Similarity threshold for pattern detection (default: 0.8)"
    )
    
    parser.add_argument(
        "--max-patterns",
        type=int,
        default=100,
        help="Maximum number of patterns to analyze (default: 100)"
    )
    
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM analysis (useful for testing or when API key is not available)"
    )
    
    parser.add_argument(
        "--visualize",
        action="store_true",
        help="Generate visualizations"
    )
    
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Generate HTML report"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the web GUI interface"
    )
    
    parser.add_argument(
        "--simple-gui",
        action="store_true",
        help="Launch the simple Tkinter GUI interface"
    )
    
    args = parser.parse_args()
    
    # Validate inputs (only for command-line mode, not GUI modes)
    if not args.gui and not args.simple_gui:
        if not args.pcap_folder:
            print("Error: --pcap-folder is required for command-line analysis.")
            sys.exit(1)
        if not os.path.exists(args.pcap_folder):
            print(f"Error: PCAP folder '{args.pcap_folder}' does not exist.")
            sys.exit(1)
    
    # Check for GUI mode
    if args.gui:
        try:
            from sharkbyte.gui import launch_gui
            print("🚀 Launching SharkByte Web GUI...")
            launch_gui()
        except ImportError:
            print("Error: Gradio not installed. Install with: pip install gradio")
            print("Alternatively, try the simple GUI: python main.py --simple-gui")
            sys.exit(1)
        except Exception as e:
            print(f"Error launching GUI: {str(e)}")
            sys.exit(1)
        return
    
    # Check for simple GUI mode
    if args.simple_gui:
        try:
            from sharkbyte.simple_gui import launch_simple_gui
            print("🚀 Launching SharkByte Simple GUI...")
            launch_simple_gui()
        except Exception as e:
            print(f"Error launching simple GUI: {str(e)}")
            sys.exit(1)
        return
    
    # Check for OpenAI API key if LLM analysis is enabled
    if not args.no_llm and not os.getenv("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY environment variable not set.")
        print("LLM analysis will be skipped. Set OPENAI_API_KEY to enable LLM analysis.")
        args.no_llm = True
    
    try:
        # Run the analysis
        results = run_analysis(
            pcap_folder=args.pcap_folder,
            output_file=args.output,
            model=args.model,
            similarity_threshold=args.similarity_threshold,
            max_patterns=args.max_patterns,
            use_llm=not args.no_llm,
            generate_visualizations=args.visualize,
            generate_html_report=args.html_report,
            verbose=args.verbose
        )
        
        print(f"\nAnalysis complete! Results saved to {args.output}")
        
        if args.visualize:
            print("Visualizations saved to 'visualizations/' directory")
        
        if args.html_report:
            print("HTML report saved to 'sharkbyte_report.html'")
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_analysis(
    pcap_folder: str,
    output_file: str,
    model: str = "gpt-4",
    similarity_threshold: float = 0.8,
    max_patterns: int = 100,
    use_llm: bool = True,
    generate_visualizations: bool = False,
    generate_html_report: bool = False,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Run the complete SharkByte analysis pipeline.
    
    Args:
        pcap_folder: Path to folder containing PCAP files
        output_file: Path to save results
        model: OpenAI model to use
        similarity_threshold: Threshold for pattern similarity
        max_patterns: Maximum patterns to analyze
        use_llm: Whether to use LLM analysis
        generate_visualizations: Whether to generate visualizations
        generate_html_report: Whether to generate HTML report
        verbose: Whether to enable verbose output
        
    Returns:
        Dictionary containing all analysis results
    """
    print("=" * 60)
    print("SHARKBYTE - LLM-Powered PCAP Analyzer")
    print("=" * 60)
    
    # Step 1: Find PCAP files
    print(f"\n1. Finding PCAP files in {pcap_folder}...")
    pcap_files = find_pcap_files(pcap_folder)
    
    if not pcap_files:
        print(f"No PCAP files found in {pcap_folder}")
        return {}
    
    print(f"Found {len(pcap_files)} PCAP file(s)")
    
    # Step 2: Analyze PCAP files
    print("\n2. Analyzing PCAP files...")
    analyzer = PCAPAnalyzer()
    analysis_results = analyzer.analyze_multiple_files(pcap_files)
    
    if verbose:
        print(f"Analysis summary:")
        print(f"  - Files processed: {analysis_results['summary']['total_files']}")
        print(f"  - Total packets: {analysis_results['summary']['total_packets']:,}")
        print(f"  - Total size: {analysis_results['summary']['total_size_mb']:.2f} MB")
    
    # Step 3: Detect patterns
    print("\n3. Detecting patterns...")
    pattern_detector = PatternDetector(similarity_threshold=similarity_threshold)
    pattern_results = pattern_detector.detect_patterns(analysis_results)
    
    if verbose:
        stats = pattern_results.get('statistics', {})
        print(f"Pattern detection summary:")
        print(f"  - Common keys: {len(pattern_results.get('common_keys', []))}")
        print(f"  - Hidden identifiers: {len(pattern_results.get('hidden_identifiers', []))}")
        print(f"  - Similar patterns: {len(pattern_results.get('similar_patterns', []))}")
    
    # Step 4: LLM Analysis (if enabled)
    llm_analysis = {}
    if use_llm:
        print("\n4. Running LLM analysis...")
        try:
            llm_analyzer = LLMAnalyzer(model=model)
            llm_analysis = llm_analyzer.analyze_patterns(pattern_results)
            
            if verbose:
                print("LLM analysis completed successfully")
                
        except Exception as e:
            print(f"Warning: LLM analysis failed: {str(e)}")
            llm_analysis = {"error": str(e)}
    else:
        print("\n4. Skipping LLM analysis (--no-llm flag used)")
    
    # Step 5: Generate visualizations (if requested)
    if generate_visualizations:
        print("\n5. Generating visualizations...")
        try:
            visualizer = Visualizer()
            visualizer.create_analysis_visualizations(analysis_results, pattern_results)
        except Exception as e:
            print(f"Warning: Visualization generation failed: {str(e)}")
    
    # Step 6: Generate HTML report (if requested)
    if generate_html_report and use_llm:
        print("\n6. Generating HTML report...")
        try:
            visualizer = Visualizer()
            visualizer.create_html_report(analysis_results, pattern_results, llm_analysis)
        except Exception as e:
            print(f"Warning: HTML report generation failed: {str(e)}")
    
    # Step 7: Save results
    print("\n7. Saving results...")
    results = {
        "analysis_results": analysis_results,
        "pattern_results": pattern_results,
        "llm_analysis": llm_analysis,
        "metadata": {
            "pcap_folder": pcap_folder,
            "files_analyzed": len(pcap_files),
            "model_used": model if use_llm else "none",
            "similarity_threshold": similarity_threshold,
            "max_patterns": max_patterns
        }
    }
    
    save_results(results, output_file)
    
    # Step 8: Print summary
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    
    summary = analysis_results.get('summary', {})
    pattern_stats = pattern_results.get('statistics', {})
    
    print(f"Files analyzed: {summary.get('total_files', 0)}")
    print(f"Total packets: {summary.get('total_packets', 0):,}")
    print(f"Total size: {summary.get('total_size_mb', 0):.2f} MB")
    print(f"Unique keys found: {pattern_stats.get('unique_keys', 0)}")
    print(f"Common keys across files: {len(pattern_results.get('common_keys', []))}")
    print(f"Hidden identifiers detected: {len(pattern_results.get('hidden_identifiers', []))}")
    print(f"Similar patterns found: {len(pattern_results.get('similar_patterns', []))}")
    
    if use_llm and 'error' not in llm_analysis:
        print(f"LLM analysis completed successfully")
    
    print("\nKey findings:")
    
    # Print some key findings
    common_keys = pattern_results.get('common_keys', [])
    if common_keys:
        print(f"  - Found {len(common_keys)} keys that appear across multiple files")
        if verbose:
            for i, key in enumerate(common_keys[:5]):
                print(f"    {i+1}. {key}")
            if len(common_keys) > 5:
                print(f"    ... and {len(common_keys) - 5} more")
    
    hidden_identifiers = pattern_results.get('hidden_identifiers', [])
    if hidden_identifiers:
        print(f"  - Detected {len(hidden_identifiers)} potential hidden identifiers")
        if verbose:
            for i, identifier in enumerate(hidden_identifiers[:3]):
                print(f"    {i+1}. Value: {identifier.get('value', 'N/A')}")
                print(f"       Files: {len(identifier.get('files', []))}")
                print(f"       Confidence: {identifier.get('confidence', 0):.2f}")
    
    print("\nAnalysis complete!")
    return results


if __name__ == "__main__":
    main()
