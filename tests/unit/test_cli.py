"""
Test the CLI module functionality.
"""

import pytest
from click.testing import CliRunner

from ghas_reporting_engine.cli import main


def test_cli_help():
    """Test that the CLI shows help information."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    
    assert result.exit_code == 0
    assert "Generate compliance reports from GitHub Advanced Security findings" in result.output
    assert "--token" in result.output
    assert "--organization" in result.output
    assert "--enterprise" in result.output


def test_cli_missing_token():
    """Test that CLI fails without a token."""
    runner = CliRunner()
    result = runner.invoke(main, ["--organization", "test-org"])
    
    assert result.exit_code != 0


def test_cli_missing_target():
    """Test that CLI fails without organization or enterprise."""
    runner = CliRunner()
    result = runner.invoke(main, ["--token", "fake-token"])
    
    assert result.exit_code == 1
    assert "Either --organization or --enterprise must be specified" in result.output


def test_cli_mutually_exclusive_targets():
    """Test that CLI fails with both organization and enterprise."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "--token", "fake-token",
        "--organization", "test-org",
        "--enterprise", "test-ent"
    ])
    
    assert result.exit_code == 1
    assert "--organization and --enterprise are mutually exclusive" in result.output