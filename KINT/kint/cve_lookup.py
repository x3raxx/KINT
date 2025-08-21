import requests
from bs4 import BeautifulSoup
from typing import Dict, Optional, List
from datetime import datetime
from kint.utils import console, print_kv_table, save_to_json, save_to_csv

class CVELookupError(Exception):
    """Custom exception for CVE lookup failures."""
    pass

def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNNN+)."""
    try:
        prefix, year, num = cve_id.split('-')
        return (prefix == 'CVE' and 
                year.isdigit() and len(year) == 4 and 
                num.isdigit() and len(num) >= 4)
    except ValueError:
        return False

def fetch_nvd_data(cve_id: str) -> Dict:
    """Fetch CVE data from NVD (National Vulnerability Database)."""
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "text/html,application/xhtml+xml"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract key fields from NVD
        fields = {
            "Title": ('span', {"data-testid": "page-header-vuln-id"}),
            "Description": ('p', {"data-testid": "vuln-description"}),
            "Severity": ('a', {"data-testid": "vuln-cvss3-panel-severity"}),
            "CVSS_Score": ('a', {"data-testid": "vuln-cvss3-panel-score"}),
            "Published_Date": ('span', {"data-testid": "vuln-published-on"}),
            "Impact_Score": ('span', {"data-testid": "vuln-cvss3-impact-score"}),
            "Exploitability_Score": ('span', {"data-testid": "vuln-cvss3-exploitability-score"}),
            "Last_Modified": ('span', {"data-testid": "vuln-last-modified-on"})
        }
        
        results = {"CVE_ID": cve_id, "Source": "NVD", "Reference": url}
        for key, (tag, attrs) in fields.items():
            element = soup.find(tag, attrs)
            results[key] = element.text.strip() if element else "N/A"
        
        # Extract affected products
        affected_products = []
        products_table = soup.find('table', {'data-testid': 'vuln-product-table'})
        if products_table:
            for row in products_table.find_all('tr')[1:]:  # Skip header
                cols = [col.text.strip() for col in row.find_all('td')]
                if len(cols) >= 3:
                    affected_products.append(f"{cols[0]} {cols[1]} ({cols[2]})")
        
        results["Affected_Products"] = affected_products or "N/A"
        return results
    
    except requests.RequestException as e:
        raise CVELookupError(f"Failed to fetch NVD data: {str(e)}")

def fetch_cve_details(cve_id: str) -> Dict:
    """Fetch additional CVE data from cvedetails.com."""
    url = f"https://www.cvedetails.com/cve/{cve_id}/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {}
        
        soup = BeautifulSoup(response.text, 'html.parser')
        details = {}
        
        # Extract CVSS metrics
        cvss_table = soup.find('table', {'id': 'cvssscorestable'})
        if cvss_table:
            for row in cvss_table.find_all('tr'):
                cols = row.find_all('td')
                if len(cols) == 2:
                    key = cols[0].text.strip().replace(' ', '_')
                    details[f"Details_{key}"] = cols[1].text.strip()
        
        # Extract vulnerability types
        vuln_types = []
        vuln_table = soup.find('table', {'id': 'vulnprodstable'})
        if vuln_table:
            for row in vuln_table.find_all('tr')[1:]:  # Skip header
                vuln_types.append(row.find('td').text.strip())
        
        details["Vulnerability_Types"] = vuln_types if vuln_types else "N/A"
        return details
    
    except requests.RequestException:
        return {}  # Silently fail for optional source

def lookup_cve(cve_id: str, export: bool = False, csv: bool = False) -> Optional[Dict]:
    """Comprehensive CVE lookup with multi-source data collection.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2023-1234")
        export: Save results as JSON
        csv: Save results as CSV
        
    Returns:
        Dictionary with CVE details or None if failed
    """
    if not validate_cve_id(cve_id):
        console.print(f"[red] Invalid CVE ID format. Expected: CVE-YYYY-NNNN+[/red]")
        return None
    
    try:
        console.print(f"[blue] Looking up [bold]{cve_id}[/bold]...[/blue]")
        
        # Get primary data from NVD
        nvd_data = fetch_nvd_data(cve_id)
        
        # Get supplemental data
        supplemental_data = fetch_cve_details(cve_id)
        
        # Combine results
        results = {**nvd_data, **supplemental_data}
        
        # Print results
        print_kv_table(f"CVE Details: {cve_id}", results)
        
        # Handle exports
        if export or csv:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{cve_id}_{timestamp}"
            
            if export:
                try:
                    save_to_json(results, f"{filename}_cve.json")
                    console.print(f"[green]✓ JSON saved to [bold]{filename}_cve.json[/bold][/green]")
                except Exception as e:
                    console.print(f"[yellow]⚠ Failed to save JSON: {str(e)}[/yellow]")
            
            if csv:
                try:
                    save_to_csv(results, f"{filename}_cve.csv")
                    console.print(f"[green]✓ CSV saved to [bold]{filename}_cve.csv[/bold][/green]")
                except Exception as e:
                    console.print(f"[yellow]⚠ Failed to save CSV: {str(e)}[/yellow]")
        
        return results
    
    except CVELookupError as e:
        console.print(f"[red] CVE lookup failed: {str(e)}[/red]")
        return None
    except Exception as e:
        console.print(f"[red] Unexpected error: {str(e)}[/red]")
        return None