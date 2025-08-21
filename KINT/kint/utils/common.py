"""
common.py - A collection of common utility functions for Python projects.
"""

import os
import sys
import json
import time
import logging
from typing import Any, Optional, Union, List, Dict, Tuple
from pathlib import Path
import datetime
import hashlib
import re

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def get_timestamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """Get current timestamp as a formatted string.
    
    Args:
        fmt: Format string for datetime (default: "%Y%m%d_%H%M%S")
    
    Returns:
        Formatted timestamp string
    """
    return datetime.datetime.now().strftime(fmt)

def read_file(file_path: Union[str, Path]) -> str:
    """Read content from a file.
    
    Args:
        file_path: Path to the file to read
    
    Returns:
        Content of the file as string
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If there's an error reading the file
    """
    path = Path(file_path) if isinstance(file_path, str) else file_path
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return path.read_text(encoding='utf-8')

def write_file(file_path: Union[str, Path], content: str, overwrite: bool = False) -> bool:
    """Write content to a file.
    
    Args:
        file_path: Path to the file to write
        content: Content to write to the file
        overwrite: Whether to overwrite if file exists (default: False)
    
    Returns:
        True if file was written successfully, False otherwise
    
    Raises:
        FileExistsError: If file exists and overwrite is False
    """
    path = Path(file_path) if isinstance(file_path, str) else file_path
    if path.exists() and not overwrite:
        raise FileExistsError(f"File already exists: {path}")
    
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    return True

def load_json(file_path: Union[str, Path]) -> Any:
    """Load JSON data from a file.
    
    Args:
        file_path: Path to the JSON file
    
    Returns:
        Parsed JSON data
    
    Raises:
        ValueError: If JSON is invalid
    """
    content = read_file(file_path)
    return json.loads(content)

def save_json(file_path: Union[str, Path], data: Any, indent: int = 2, overwrite: bool = False) -> bool:
    """Save data to a JSON file.
    
    Args:
        file_path: Path to the JSON file
        data: Data to save (must be JSON serializable)
        indent: Indentation level for pretty printing (default: 2)
        overwrite: Whether to overwrite if file exists (default: False)
    
    Returns:
        True if file was written successfully
    
    Raises:
        TypeError: If data is not JSON serializable
    """
    json_str = json.dumps(data, indent=indent, ensure_ascii=False)
    return write_file(file_path, json_str, overwrite)

def hash_string(text: str, algorithm: str = "sha256") -> str:
    """Generate hash of a string.
    
    Args:
        text: Input string to hash
        algorithm: Hashing algorithm (default: "sha256")
    
    Returns:
        Hexadecimal hash string
    
    Raises:
        ValueError: If unsupported algorithm is specified
    """
    hasher = hashlib.new(algorithm)
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def validate_email(email: str) -> bool:
    """Validate an email address format.
    
    Args:
        email: Email address to validate
    
    Returns:
        True if email format is valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def retry(max_attempts: int = 3, delay: float = 1, exceptions: Tuple = (Exception,)):
    """Decorator for retrying a function upon failure.
    
    Args:
        max_attempts: Maximum number of attempts (default: 3)
        delay: Delay between attempts in seconds (default: 1)
        exceptions: Tuple of exceptions to catch (default: (Exception,))
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    logger.warning(f"Attempt {attempt} failed: {str(e)}")
                    if attempt < max_attempts:
                        time.sleep(delay)
            raise last_exception
        return wrapper
    return decorator

def human_readable_size(size: int, decimal_places: int = 2) -> str:
    """Convert bytes to human-readable format.
    
    Args:
        size: Size in bytes
        decimal_places: Number of decimal places to show
    
    Returns:
        Human-readable size string (e.g., "1.23 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split a list into chunks of specified size.
    
    Args:
        lst: List to split
        chunk_size: Size of each chunk
    
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def timeit(func):
    """Decorator to measure execution time of a function."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logger.info(f"Function {func.__name__} executed in {end_time - start_time:.4f} seconds")
        return result
    return wrapper

if __name__ == "__main__":
    # Example usage
    print(f"Current timestamp: {get_timestamp()}")
    print(f"SHA256 hash of 'hello': {hash_string('hello')}")
    print(f"Human readable size: {human_readable_size(123456789)}")
