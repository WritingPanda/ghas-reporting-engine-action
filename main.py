"""
Main entry point for GHAS Reporting Engine.

This module provides backward compatibility and can be used for development.
The main CLI is now in src/ghas_reporting_engine/cli.py
"""

from src.ghas_reporting_engine.cli import main

if __name__ == "__main__":
    main()
