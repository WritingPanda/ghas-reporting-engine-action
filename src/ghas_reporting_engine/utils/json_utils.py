"""
JSON serialization utilities for GHAS Reporting Engine.

This module provides utilities to safely serialize complex objects to JSON,
handling Pydantic models and other non-serializable objects.
"""

import json
from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel


def sanitize_for_json(obj: Any) -> Any:
    """
    Recursively sanitize an object for JSON serialization.
    
    This function converts Pydantic models to dictionaries and handles
    other non-serializable objects like datetime objects and methods.
    """
    if obj is None:
        return None
    elif isinstance(obj, BaseModel):
        # Convert Pydantic model to dict, excluding methods
        return {k: sanitize_for_json(v) for k, v in obj.__dict__.items() 
                if not callable(v)}
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    elif isinstance(obj, set):
        return [sanitize_for_json(item) for item in obj]
    elif callable(obj):
        # Skip functions and methods
        return None
    elif hasattr(obj, '__dict__'):
        # Handle other objects with attributes
        return {k: sanitize_for_json(v) for k, v in obj.__dict__.items() 
                if not k.startswith('_') and not callable(v)}
    else:
        # Basic types (str, int, float, bool)
        return obj


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """
    Safely serialize an object to JSON string.
    
    Uses the sanitize_for_json function to handle complex objects.
    """
    sanitized = sanitize_for_json(obj)
    return json.dumps(sanitized, **kwargs)


class SafeJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that handles complex objects safely.
    """
    
    def default(self, o: Any) -> Any:
        if isinstance(o, BaseModel):
            # For Pydantic models, use dict() method but exclude methods
            model_dict = o.dict()
            return {k: v for k, v in model_dict.items() if not callable(v)}
        elif isinstance(o, datetime):
            return o.isoformat()
        elif callable(o):
            return str(o)
        else:
            return super().default(o)