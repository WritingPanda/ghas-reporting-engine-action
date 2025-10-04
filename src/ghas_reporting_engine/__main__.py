"""
Main entry point for the GHAS Reporting Engine module.

This allows the package to be executed as a module using:
python -m ghas_reporting_engine
"""

from .cli import cli

if __name__ == "__main__":
    cli()