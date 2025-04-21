#!/usr/bin/env python
"""
Entry point for the privacy-preserving digital credential system.
"""

import os
import sys
import argparse

from demo.cli import cli
from demo.web import app


def main():
    """Run the application."""
    parser = argparse.ArgumentParser(description='Privacy-Preserving Digital Credential System')
    parser.add_argument('--web', action='store_true', help='Run the web interface')
    parser.add_argument('--cli', action='store_true', help='Run the CLI interface')
    parser.add_argument('--port', type=int, default=5000, help='Port for web server (default: 5000)')
    args, remaining_args = parser.parse_known_args()
    
    if args.web:
        # Run web interface
        app.run(debug=True, port=args.port)
    elif args.cli or len(sys.argv) == 1:
        # Run CLI interface with any remaining arguments
        sys.argv = [sys.argv[0]] + remaining_args
        cli()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()