#!/usr/bin/env python3
import argparse
import sys
from typing import Optional, Dict
import re
import ipaddress
from functools import wraps
import time

# Third-party imports
try:
    from kint import cve_lookup, ip_lookup, domain_lookup
    from kint.utils import console, print_kv_table, save_to_json, save_to_csv
except ImportError as e:
    print(f"Error: Required kint package not found. Please install it first.\n{e}")
    sys.exit(1)

# Configuration
MAX_RETRIES = 2
RETRY_DELAY = 0.5  # seconds

def retry_on_failure(func):
    """Simple retry decorator for basic fault tolerance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        last_error = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * (attempt + 1))
        print(f"\nError: Operation failed after {MAX_RETRIES} attempts", file=sys.stderr)
        raise last_error
    return wrapper

def validate_input(value: str, input_type: str) -> bool:
    """Basic input validation without raising exceptions"""
    try:
        if input_type == 'cve':
            return value.upper().startswith('CVE-') and bool(re.match(r'^CVE-\d{4}-\d+$', value))
        elif input_type == 'ip':
            ipaddress.ip_address(value)
            return True
        elif input_type == 'domain':
            return bool(re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', value, re.IGNORECASE))
    except ValueError:
        return False
    return False

@retry_on_failure
def safe_lookup(lookup_type: str, value: str, export: bool, csv: bool) -> Optional[Dict]:
    """Unified lookup function with basic error handling"""
    lookup_functions = {
        'cve': cve_lookup.lookup_cve,
        'ip': ip_lookup.lookup_ip,
        'domain': domain_lookup.lookup_domain
    }
    
    if not validate_input(value, lookup_type):
        print(f"Error: Invalid {lookup_type} format: {value}", file=sys.stderr)
        return None

    try:
        result = lookup_functions[lookup_type](value)
        if not result:
            print(f"No results found for {lookup_type}: {value}", file=sys.stderr)
            return None

        # Handle exports
        filename_prefix = f"{lookup_type}_{value.replace('.', '_')}"
        if export:
            save_to_json(result, f"{filename_prefix}.json")
        if csv:
            save_to_csv(result, f"{filename_prefix}.csv")
            
        return result
        
    except Exception as e:
        print(f"\nError processing {lookup_type} {value}: {str(e)}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(
        description="KINT Personal - Simple Threat Intelligence Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Lookup Commands
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cve', help='Lookup CVE details (e.g., CVE-2021-44228)')
    group.add_argument('--ip', help='Lookup IP information')
    group.add_argument('--domain', help='Lookup domain WHOIS')
    
    # Output Options
    parser.add_argument('--export', action='store_true', help='Save results to JSON')
    parser.add_argument('--csv', action='store_true', help='Save results to CSV')
    
    args = parser.parse_args()
    
    try:
        if args.cve:
            safe_lookup('cve', args.cve.upper(), args.export, args.csv)
        elif args.ip:
            safe_lookup('ip', args.ip, args.export, args.csv)
        elif args.domain:
            safe_lookup('domain', args.domain.lower(), args.export, args.csv)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
