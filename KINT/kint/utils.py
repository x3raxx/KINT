from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.markdown import Markdown
import json
import csv
import logging
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
import functools
import time

# Initialize console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('kint.log'),
        logging.StreamHandler()
    ]
)

# Cache configuration
CACHE_DB = "kint_cache.db"
CACHE_TTL_HOURS = 24

def init_cache():
    """Initialize SQLite cache database"""
    with sqlite3.connect(CACHE_DB) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT,
            expiry TIMESTAMP,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_expiry ON cache(expiry)")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS api_limits (
            endpoint TEXT PRIMARY KEY,
            last_call TIMESTAMP,
            call_count INTEGER DEFAULT 0
        )
        """)

def cache_result(key: str, ttl: int = CACHE_TTL_HOURS):
    """
    Decorator to cache function results with automatic invalidation
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}_{key}_{str(args)}_{str(kwargs)}"
            
            # Try to get cached result
            with sqlite3.connect(CACHE_DB) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT value FROM cache WHERE key = ? AND expiry > ?",
                    (cache_key, datetime.now())
                )
                result = cursor.fetchone()
                
                if result:
                    logging.info(f"Using cached result for {func.__name__}")
                    return eval(result[0])
                
            # Cache miss - execute function
            fresh_result = func(*args, **kwargs)
            
            # Store result in cache
            with sqlite3.connect(CACHE_DB) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cache (key, value, expiry) VALUES (?, ?, ?)",
                    (cache_key, str(fresh_result), datetime.now() + timedelta(hours=ttl))
                )
            
            return fresh_result
        return wrapper
    return decorator

def rate_limited(max_calls: int, period: int):
    """
    Decorator to implement rate limiting for API calls
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = func.__name__
            
            with sqlite3.connect(CACHE_DB) as conn:
                # Get current rate limit status
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT last_call, call_count FROM api_limits WHERE endpoint = ?",
                    (endpoint,)
                )
                result = cursor.fetchone()
                
                now = datetime.now()
                if result:
                    last_call, call_count = result
                    last_call = datetime.strptime(last_call, "%Y-%m-%d %H:%M:%S.%f")
                    time_since = (now - last_call).total_seconds()
                    
                    if time_since < period:
                        if call_count >= max_calls:
                            wait_time = period - time_since
                            logging.warning(f"Rate limit exceeded. Waiting {wait_time:.1f} seconds")
                            time.sleep(wait_time)
                            call_count = 0
                    else:
                        call_count = 0
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Update rate limit status
                conn.execute(
                    "INSERT OR REPLACE INTO api_limits (endpoint, last_call, call_count) VALUES (?, ?, ?)",
                    (endpoint, now, call_count + 1)
                )
                
                return result
        return wrapper
    return decorator

def print_kv_table(title: str, data: Union[Dict[Any, Any], List[Dict[Any, Any]]], **kwargs) -> None:
    """
    Enhanced key-value table printer with support for both single and multiple records
    """
    table = Table(title=title, **kwargs)
    table.add_column("Title", style="#9c6137", no_wrap=True)
    table.add_column("Info", style="#009bd3")
    
    if isinstance(data, dict):
        for key, value in data.items():
            table.add_row(str(key), str(value))
    elif isinstance(data, list) and all(isinstance(x, dict) for x in data):
        for item in data:
            for key, value in item.items():
                table.add_row(str(key), str(value))
            table.add_section()
    else:
        raise TypeError("Data must be a dictionary or list of dictionaries")
    
    console.print(table)

def save_to_json(data: Any, filename: str, indent: int = 2) -> None:
    """
    Enhanced JSON saver with automatic file extension handling and pretty printing
    """
    try:
        if not filename.endswith(".json"):
            filename += ".json"
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)
        
        logging.info(f"Successfully saved JSON to {filename}")
        console.print(f"[green]✓ JSON saved to [bold]{filename}[/bold][/green]")
    except Exception as e:
        logging.error(f"Failed to save JSON: {str(e)}")
        console.print(f"[red]✗ Failed to save JSON: {str(e)}[/red]")
        raise

def save_to_csv(data: Union[Dict, List[Dict]], filename: str) -> None:
    """
    Enhanced CSV saver with support for both single and multiple records
    """
    try:
        if not filename.endswith(".csv"):
            filename += ".csv"
        
        if isinstance(data, dict):
            data = [data]
        
        if not data or not all(isinstance(x, dict) for x in data):
            raise ValueError("Data must be a dictionary or list of dictionaries")
        
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())
        
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            writer.writerows(data)
        
        logging.info(f"Successfully saved CSV to {filename}")
        console.print(f"[green]✓ CSV saved to [bold]{filename}[/bold][/green]")
    except Exception as e:
        logging.error(f"Failed to save CSV: {str(e)}")
        console.print(f"[red]✗ Failed to save CSV: {str(e)}[/red]")
        raise

def progress_spinner(description: str = "Processing..."):
    """
    Context manager for displaying a spinner during operations
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    )

def clear_cache() -> None:
    """
    Clear all cached data and reset rate limits
    """
    try:
        Path(CACHE_DB).unlink(missing_ok=True)
        init_cache()
        logging.info("Cache cleared successfully")
        console.print("[green]✓ Cache cleared successfully[/green]")
    except Exception as e:
        logging.error(f"Failed to clear cache: {str(e)}")
        console.print(f"[red]✗ Failed to clear cache: {str(e)}[/red]")
        raise

def display_markdown(content: str) -> None:
    """
    Render and display markdown content
    """
    console.print(Markdown(content))

def display_panel(title: str, content: str, style: str = "blue") -> None:
    """
    Display content in a rich panel
    """
    console.print(Panel(content, title=title, style=style))

# Initialize cache on import
init_cache()