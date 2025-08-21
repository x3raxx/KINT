import subprocess
import requests
from typing import Dict, Optional
from kint.utils import console, print_kv_table, save_to_json, save_to_csv

class IPLookupError(Exception):
    """Custom exception for IP lookup failures."""
    pass

def get_whois_info(ip: str) -> str:
    """Retrieve WHOIS information for an IP address.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        WHOIS information as string
        
    Raises:
        IPLookupError: If whois command fails
    """
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise IPLookupError(f"WHOIS lookup failed: {e.stderr}") from e
    except Exception as e:
        raise IPLookupError(f"Unexpected WHOIS error: {str(e)}") from e

def get_geo_info(ip: str) -> Dict:
    """Retrieve geographical information for an IP address from ipinfo.io.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Dictionary containing geo information
        
    Raises:
        IPLookupError: If API request fails
    """
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise IPLookupError(f"Geo IP API request failed: {str(e)}") from e
    except ValueError as e:
        raise IPLookupError(f"Failed to parse Geo IP response: {str(e)}") from e

def lookup_ip(ip: str, export: bool = False, csv: bool = False) -> Optional[Dict]:
    """Perform comprehensive IP address lookup including WHOIS and geographical data.
    
    Args:
        ip: IP address to lookup
        export: Whether to save results as JSON
        csv: Whether to save results as CSV
        
    Returns:
        Dictionary containing lookup results if successful, None otherwise
    """
    results = {"IP": ip}
    
    try:
        # Get WHOIS information
        whois_result = get_whois_info(ip)
        results["WHOIS"] = (
            whois_result[:500] + "..." 
            if len(whois_result) > 500 
            else whois_result
        )
        
        # Get geographical information
        geo = get_geo_info(ip)
        geo_fields = {
            "City": "city",
            "Region": "region",
            "Country": "country",
            "Org": "org"
        }
        
        for display_field, api_field in geo_fields.items():
            results[display_field] = geo.get(api_field, "N/A")
        
        # Display results
        print_kv_table("IP Information", results)
        
        # Export results if requested
        if export:
            save_to_json(results, f"{ip}_ip.json")
            console.print(f"[green]✓ Results saved to {ip}_ip.json[/green]")
            
        if csv:
            save_to_csv(results, f"{ip}_ip.csv")
            console.print(f"[green]✓ Results saved to {ip}_ip.csv[/green]")
            
        return results
        
    except IPLookupError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error during IP lookup: {str(e)}[/red]")
        return None