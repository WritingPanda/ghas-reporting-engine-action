"""
JSON utilities for safe serialization.

Provides utilities for safely serializing complex objects to JSON.
"""

import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any


def sanitize_for_json(obj: Any) -> Any:
    """
    Recursively sanitize an object for JSON serialization.
    
    Handles datetime, date, Path, Enum, sets, and complex nested structures.
    """
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    
    if isinstance(obj, Path):
        return str(obj)
    
    if isinstance(obj, Enum):
        return obj.value
    
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    
    # For custom objects, try to get __dict__
    if hasattr(obj, "__dict__"):
        return sanitize_for_json(obj.__dict__)
    
    # Fallback to string representation
    return str(obj)


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """
    Safely serialize an object to JSON string.
    
    Args:
        obj: Object to serialize
        **kwargs: Additional arguments to pass to json.dumps
        
    Returns:
        JSON string representation
    """
    sanitized = sanitize_for_json(obj)
    return json.dumps(sanitized, **kwargs)
