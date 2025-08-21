import subprocess
from typing import Dict, Optional
from kint.utils import console, print_kv_table, save_to_json, save_to_csv

class DomainLookupError(Exception):
    """Custom exception for domain lookup failures."""
    pass

def validate_domain(domain: str) -> bool:
    """Basic domain validation to prevent command injection.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        bool: True if domain appears valid, False otherwise
    """
    # Basic checks - expand this for your specific needs
    if not domain or len(domain) > 253:
        return False
    if " " in domain or ";" in domain or "|" in domain:
        return False
    return True

def get_whois_info(domain: str) -> str:
    """Safely retrieve WHOIS information for a domain.
    
    Args:
        domain: Domain name to lookup
        
    Returns:
        WHOIS information as string
        
    Raises:
        DomainLookupError: If whois command fails or domain is invalid
    """
    if not validate_domain(domain):
        raise DomainLookupError(f"Invalid domain format: {domain}")

    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            check=True,
            timeout=10  # Prevent hanging
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise DomainLookupError("WHOIS lookup timed out (10s)")
    except subprocess.CalledProcessError as e:
        raise DomainLookupError(f"WHOIS lookup failed: {e.stderr.strip() or 'Unknown error'}")
    except Exception as e:
        raise DomainLookupError(f"Unexpected WHOIS error: {str(e)}")

def lookup_domain(domain: str, export: bool = False, csv: bool = False) -> Optional[Dict]:
    """Perform domain WHOIS lookup and optionally save results.
    
    Args:
        domain: Domain name to lookup
        export: Whether to save results as JSON
        csv: Whether to save results as CSV
        
    Returns:
        Dictionary containing lookup results if successful, None otherwise
        
    Example:
        >>> lookup_domain("example.com", export=True)
    """
    results = {"Domain": domain}
    
    try:
        whois_result = get_whois_info(domain)
        results["WHOIS"] = (
            whois_result[:500] + "... [truncated]" 
            if len(whois_result) > 500 
            else whois_result
        )
        
        # Print results in a formatted table
        print_kv_table("Domain WHOIS Information", results)
        
        # Handle export options
        if export:
            try:
                save_to_json(results, f"{domain}_domain.json")
                console.print(f"[green]✓ Results saved to {domain}_domain.json[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠ Failed to save JSON: {str(e)}[/yellow]")
                
        if csv:
            try:
                save_to_csv(results, f"{domain}_domain.csv")
                console.print(f"[green]✓ Results saved to {domain}_domain.csv[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠ Failed to save CSV: {str(e)}[/yellow]")
        
        return results
        
    except DomainLookupError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error during domain lookup: {str(e)}[/red]")
        return None
