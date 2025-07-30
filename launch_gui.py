#!/usr/bin/env python3
"""
SharkByte GUI Launcher

Simple script to launch the SharkByte web interface.
"""

import argparse
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sharkbyte.gui import launch_gui


def main():
    """Main entry point for the GUI launcher."""
    parser = argparse.ArgumentParser(
        description="SharkByte GUI Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launch_gui.py                    # Launch with default settings
  python launch_gui.py --port 8080       # Launch on port 8080
  python launch_gui.py --host 127.0.0.1  # Launch on localhost only
  python launch_gui.py --share           # Create public link
        """
    )
    
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=7860,
        help="Port to bind to (default: 7860)"
    )
    
    parser.add_argument(
        "--share",
        action="store_true",
        help="Create a public link for sharing"
    )
    
    args = parser.parse_args()
    
    print("🦈 SharkByte GUI Launcher")
    print("=" * 40)
    print(f"🌐 Server: {args.host}:{args.port}")
    if args.share:
        print("🔗 Public link will be generated")
    print("=" * 40)
    
    try:
        launch_gui(
            server_name=args.host,
            server_port=args.port,
            share=args.share
        )
    except KeyboardInterrupt:
        print("\n👋 GUI stopped by user")
    except Exception as e:
        print(f"❌ Error launching GUI: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 