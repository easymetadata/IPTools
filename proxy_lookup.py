#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# Version 1.0
# Date: 2026-01-19
# This module contains utility functions for IP proxy lookup using IP2Proxy data

import csv
import ipaddress
import logging
import multiprocessing
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import pandas as pd

# Try to import IP2Proxy library (optional)
try:
    import IP2Proxy
    IP2PROXY_AVAILABLE = True
except ImportError:
    IP2PROXY_AVAILABLE = False
    logging.warning("IP2Proxy library not available. CSV-based lookup will be used.")

def _process_proxy_chunk(args_tuple):
    """
    Process a chunk of IPs for proxy lookup. Must be at module level for multiprocessing.

    Args:
        args_tuple: Tuple of (ip_chunk, data_path, use_csv)

    Returns:
        List[ProxyResult]: List of proxy lookup results for the chunk
    """
    ip_chunk, data_path, use_csv = args_tuple
    results = []

    try:
        # Create a local ProxyLookup instance for this worker
        lookup = ProxyLookup(data_path, use_csv=use_csv)

        for ip in ip_chunk:
            try:
                result = lookup.lookup_proxy(ip)
                results.append(result)
            except Exception as e:
                logging.error(f"Error processing IP {ip}: {e}")
                failed_result = ProxyResult(ip=ip)
                failed_result.notes = f"Processing failed: {e}"
                results.append(failed_result)

        lookup.close()

    except Exception as e:
        logging.error(f"Error initializing lookup in worker: {e}")
        # Return failed results for all IPs in chunk
        for ip in ip_chunk:
            failed_result = ProxyResult(ip=ip)
            failed_result.notes = f"Worker initialization failed: {e}"
            results.append(failed_result)

    return results


# Define Result class to match project structure
class ProxyResult:
    def __init__(self, ip='', is_proxy=False, proxy_type='', country_code='', country_name='', 
                 region='', city='', isp='', domain='', usage_type='', asn='', as_name='', 
                 last_seen='', threat='', provider='', fraud_score='', notes=''):
        self.ip = ip
        self.is_proxy = is_proxy
        self.proxy_type = proxy_type
        self.country_code = country_code
        self.country_name = country_name
        self.region = region
        self.city = city
        self.isp = isp
        self.domain = domain
        self.usage_type = usage_type
        self.asn = asn
        self.as_name = as_name
        self.last_seen = last_seen
        self.threat = threat
        self.provider = provider
        self.fraud_score = fraud_score
        self.notes = notes

class ProxyLookup:
    """
    IP Proxy Lookup utility using IP2Proxy data.
    Supports both BIN database files and CSV data files.
    """
    
    def __init__(self, data_path: str = "IP2PROXY-LITE-PX12", use_csv: bool = False):
        """
        Initialize the proxy lookup utility.

        Args:
            data_path (str): Path to IP2Proxy data directory or BIN file
            use_csv (bool): Force CSV lookup instead of BIN (BIN is default and faster)
        """
        self.data_path = Path(data_path)
        # Use BIN by default if available, unless CSV is explicitly requested
        self.use_bin = IP2PROXY_AVAILABLE and not use_csv
        self.db = None
        self.csv_data = None
        self.csv_columns = []

        # Initialize based on available data - prefer BIN for performance
        if self.use_bin:
            self._init_bin_database()
        else:
            self._init_csv_database()
    
    def _init_bin_database(self):
        """Initialize IP2Proxy BIN database."""
        try:
            if not IP2PROXY_AVAILABLE:
                raise ImportError("IP2Proxy library not available")
            
            # Look for BIN file in the data directory
            bin_files = list(self.data_path.glob("*.BIN"))
            if not bin_files:
                bin_files = list(self.data_path.glob("*.bin"))
            
            if bin_files:
                bin_file = bin_files[0]
                self.db = IP2Proxy.IP2Proxy()
                self.db.open(str(bin_file))
                logging.info(f"Initialized IP2Proxy BIN database: {bin_file}")
            else:
                logging.warning("No BIN file found, falling back to CSV")
                self.use_bin = False
                self._init_csv_database()
                
        except Exception as e:
            logging.error(f"Failed to initialize BIN database: {e}")
            self.use_bin = False
            self._init_csv_database()
    
    def _init_csv_database(self):
        """Initialize CSV-based proxy database."""
        try:
            csv_file = self.data_path / "IP2PROXY-LITE-PX12.CSV"
            if not csv_file.exists():
                raise FileNotFoundError(f"CSV file not found: {csv_file}")
            
            # Read CSV headers to understand structure
            with open(csv_file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                self.csv_columns = [col.strip('"') for col in first_line.split('","')]
            
            logging.info(f"Initialized CSV database with {len(self.csv_columns)} columns")
            logging.debug(f"CSV columns: {self.csv_columns}")
            
        except Exception as e:
            logging.error(f"Failed to initialize CSV database: {e}")
            raise
    
    def _ip_to_long(self, ip_address: str) -> int:
        """Convert IP address to long integer for comparison."""
        try:
            return int(ipaddress.IPv4Address(ip_address))
        except ipaddress.AddressValueError:
            return 0
    
    def _binary_search_csv(self, ip_long: int) -> Optional[Dict]:
        """
        Perform binary search on CSV data to find proxy information.
        
        Args:
            ip_long (int): IP address as long integer
            
        Returns:
            Optional[Dict]: Proxy information if found, None otherwise
        """
        csv_file = self.data_path / "IP2PROXY-LITE-PX12.CSV"
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                
                for row in reader:
                    if len(row) >= 2:
                        start_ip = int(row[0].strip('"'))
                        end_ip = int(row[1].strip('"'))
                        
                        if start_ip <= ip_long <= end_ip:
                            # Found matching range, return data
                            return self._parse_csv_row(row)
            
            return None
            
        except Exception as e:
            logging.error(f"Error searching CSV: {e}")
            return None
    
    def _parse_csv_row(self, row: List[str]) -> Dict:
        """
        Parse CSV row into structured proxy data.
        
        Args:
            row (List[str]): CSV row data
            
        Returns:
            Dict: Parsed proxy information
        """
        # Expected columns based on IP2Proxy LITE PX9 format:
        # start_ip, end_ip, proxy_type, country_code, country_name, region, city, 
        # isp, domain, usage_type, asn, as_name, last_seen, threat
        
        data = {}
        
        if len(row) >= 14:
            data = {
                'start_ip': row[0].strip('"'),
                'end_ip': row[1].strip('"'),
                'proxy_type': row[2].strip('"'),
                'country_code': row[3].strip('"'),
                'country_name': row[4].strip('"'),
                'region': row[5].strip('"'),
                'city': row[6].strip('"'),
                'isp': row[7].strip('"'),
                'domain': row[8].strip('"'),
                'usage_type': row[9].strip('"'),
                'asn': row[10].strip('"'),
                'as_name': row[11].strip('"'),
                'last_seen': row[12].strip('"'),
                'threat': row[13].strip('"')
            }
        
        return data
    
    def lookup_proxy(self, ip_address: str) -> ProxyResult:
        """
        Lookup proxy information for an IP address.
        
        Args:
            ip_address (str): IP address to lookup
            
        Returns:
            ProxyResult: Proxy information result
        """
        result = ProxyResult(ip=ip_address)
        
        try:
            if self.use_bin and self.db:
                return self._lookup_bin(ip_address)
            else:
                return self._lookup_csv(ip_address)
                
        except Exception as e:
            logging.error(f"Error looking up proxy for {ip_address}: {e}")
            result.notes = f"Error: {str(e)}"
            return result
    
    def _lookup_bin(self, ip_address: str) -> ProxyResult:
        """Lookup using IP2Proxy BIN database."""
        result = ProxyResult(ip=ip_address)
        
        try:
            record = self.db.get_all(ip_address)
            
            result.is_proxy = record.get('is_proxy', False)
            result.proxy_type = record.get('proxy_type', '')
            result.country_code = record.get('country_short', '')
            result.country_name = record.get('country_long', '')
            result.region = record.get('region', '')
            result.city = record.get('city', '')
            result.isp = record.get('isp', '')
            result.domain = record.get('domain', '')
            result.usage_type = record.get('usage_type', '')
            result.asn = record.get('asn', '')
            result.as_name = record.get('as_name', '')
            result.last_seen = record.get('last_seen', '')
            result.threat = record.get('threat', '')
            result.provider = record.get('provider', '')
            result.fraud_score = record.get('fraud_score', '')
            
        except Exception as e:
            logging.error(f"BIN lookup error for {ip_address}: {e}")
            result.notes = f"BIN lookup error: {str(e)}"
        
        return result
    
    def _lookup_csv(self, ip_address: str) -> ProxyResult:
        """Lookup using CSV database."""
        result = ProxyResult(ip=ip_address)
        
        try:
            ip_long = self._ip_to_long(ip_address)
            if ip_long == 0:
                result.notes = "Invalid IP address"
                return result
            
            proxy_data = self._binary_search_csv(ip_long)
            
            if proxy_data:
                result.is_proxy = proxy_data.get('proxy_type', '') != '-'
                result.proxy_type = proxy_data.get('proxy_type', '')
                result.country_code = proxy_data.get('country_code', '')
                result.country_name = proxy_data.get('country_name', '')
                result.region = proxy_data.get('region', '')
                result.city = proxy_data.get('city', '')
                result.isp = proxy_data.get('isp', '')
                result.domain = proxy_data.get('domain', '')
                result.usage_type = proxy_data.get('usage_type', '')
                result.asn = proxy_data.get('asn', '')
                result.as_name = proxy_data.get('as_name', '')
                result.last_seen = proxy_data.get('last_seen', '')
                result.threat = proxy_data.get('threat', '')
                
                if result.is_proxy:
                    result.notes = "Proxy detected via CSV lookup"
                else:
                    result.notes = "No proxy detected via CSV lookup"
            else:
                result.notes = "IP not found in proxy database"
                
        except Exception as e:
            logging.error(f"CSV lookup error for {ip_address}: {e}")
            result.notes = f"CSV lookup error: {str(e)}"
        
        return result
    
    def batch_lookup(self, ip_addresses: List[str], num_processes: int = None,
                      chunk_size: int = None, show_progress: bool = True) -> List[ProxyResult]:
        """
        Perform batch proxy lookup for multiple IP addresses using multiprocessing.

        Args:
            ip_addresses (List[str]): List of IP addresses to lookup
            num_processes (int): Number of processes to use (default: auto-detect)
            chunk_size (int): Size of IP chunks for processing (default: auto-calculate)
            show_progress (bool): Whether to show progress output

        Returns:
            List[ProxyResult]: List of proxy lookup results
        """
        start_time = time.time()

        if not ip_addresses:
            return []

        # For small batches, use single-threaded processing
        if len(ip_addresses) < 10:
            results = []
            for ip in ip_addresses:
                result = self.lookup_proxy(ip)
                results.append(result)
            elapsed = time.time() - start_time
            if show_progress:
                print(f'Batch lookup completed in {elapsed:.2f} seconds ({len(results)} IPs)')
            return results

        # Determine number of processes
        if num_processes is None:
            num_processes = min(multiprocessing.cpu_count(), len(ip_addresses))
        else:
            num_processes = min(num_processes, len(ip_addresses))

        # Calculate chunk size
        if chunk_size is None:
            chunk_size = max(1, min(50, len(ip_addresses) // (num_processes * 2)))

        if show_progress:
            print(f'Using {num_processes} processes with chunk size {chunk_size}')

        # Create chunks of IPs
        ip_chunks = [ip_addresses[i:i + chunk_size] for i in range(0, len(ip_addresses), chunk_size)]

        if show_progress:
            print(f'Created {len(ip_chunks)} chunks for processing...')

        # Prepare arguments for worker function
        data_path_str = str(self.data_path)
        use_csv = not self.use_bin  # Invert: use_csv=True means don't use BIN

        try:
            with multiprocessing.Pool(processes=num_processes, maxtasksperchild=100) as pool:
                total_chunks = len(ip_chunks)
                chunk_results = []

                # Process chunks with progress tracking
                for i, chunk_result in enumerate(pool.imap(
                    _process_proxy_chunk,
                    [(chunk, data_path_str, use_csv) for chunk in ip_chunks]
                )):
                    chunk_results.append(chunk_result)
                    if show_progress and (i + 1) % max(1, total_chunks // 10) == 0:
                        print(f'Progress: {i + 1}/{total_chunks} chunks completed ({(i + 1) * 100 // total_chunks}%)')

                # Flatten results from all chunks
                results = []
                for chunk_result in chunk_results:
                    results.extend(chunk_result)

                elapsed = time.time() - start_time
                if show_progress:
                    ips_per_sec = len(results) / elapsed if elapsed > 0 else 0
                    print(f'Processed {len(results)} IPs in {elapsed:.2f} seconds ({ips_per_sec:.1f} IPs/sec)')

                return results

        except Exception as e:
            logging.error(f'Error during multiprocessing: {e}')
            if show_progress:
                print(f'Multiprocessing failed, falling back to single-threaded: {e}')

            # Fallback to single-threaded processing
            results = []
            for ip in ip_addresses:
                result = self.lookup_proxy(ip)
                results.append(result)

            elapsed = time.time() - start_time
            if show_progress:
                ips_per_sec = len(results) / elapsed if elapsed > 0 else 0
                print(f'Processed {len(results)} IPs in {elapsed:.2f} seconds ({ips_per_sec:.1f} IPs/sec)')
            return results
    
    def get_proxy_summary(self, results: List[ProxyResult]) -> Dict:
        """
        Get summary statistics for proxy detection from results.

        Args:
            results (List[ProxyResult]): List of proxy lookup results

        Returns:
            Dict: Summary statistics
        """
        total_ips = len(results)
        proxy_count = sum(1 for r in results if r.is_proxy)
        proxy_types = {}
        countries = {}
        domains = {}
        last_seen_dates = {}
        threats = {}
        
        for result in results:
            if result.is_proxy:
                # Count proxy types
                proxy_type = result.proxy_type or 'Unknown'
                proxy_types[proxy_type] = proxy_types.get(proxy_type, 0) + 1
                
                # Count countries
                country = result.country_code or 'Unknown'
                countries[country] = countries.get(country, 0) + 1
                
                # Count domains
                domain = result.domain or 'Unknown'
                domains[domain] = domains.get(domain, 0) + 1
                
                # Count last seen dates
                last_seen = result.last_seen or 'Unknown'
                last_seen_dates[last_seen] = last_seen_dates.get(last_seen, 0) + 1
                
                # Count threats
                threat = result.threat or 'None'
                threats[threat] = threats.get(threat, 0) + 1
        
        return {
            'total_ips': total_ips,
            'proxy_count': proxy_count,
            'proxy_percentage': (proxy_count / total_ips * 100) if total_ips > 0 else 0,
            'proxy_types': proxy_types,
            'proxy_countries': countries,
            'proxy_domains': domains,
            'proxy_last_seen': last_seen_dates,
            'proxy_threats': threats,
            'results': results
        }
    
    def generate_html_report(self, results: List[ProxyResult], summary: Dict = None) -> str:
        """
        Generate HTML report with proxy lookup results.
        
        Args:
            results (List[ProxyResult]): List of proxy lookup results
            summary (Dict): Optional summary statistics
            
        Returns:
            str: HTML formatted report
        """
        html = []
        
        # HTML header
        html.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Proxy Lookup Report</title>
    <style>
        /* Optimized for 1920x1080 screens */
        body { font-family: Arial, sans-serif; font-size: 11px; margin: 0; padding-top: 50px; background-color: #f5f5f5; }
        .container { max-width: 1880px; margin: 0 auto; background-color: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        #nav-ribbon { position: fixed; top: 0; left: 0; width: 100%; background-color: #2c3e50; padding: 6px 0; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); z-index: 1000; }
        .nav-btn { display: inline-block; color: white; text-decoration: none; padding: 5px 14px; margin: 0 4px; border-radius: 15px; background-color: rgba(255,255,255,0.1); transition: background 0.3s; font-size: 11px; }
        .nav-btn:hover { background-color: #007bff; }
        .section-anchor { scroll-margin-top: 60px; }
        .distribution-wrapper { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
        .distribution-col { flex: 1; min-width: 220px; }
        .compact-table { width: 100%; border-collapse: collapse; font-size: 10px; }
        .compact-table th { background-color: #e9ecef; color: #495057; padding: 4px 6px; text-align: left; border-bottom: 2px solid #dee2e6; }
        .compact-table td { padding: 3px 6px; border-bottom: 1px solid #dee2e6; }
        .compact-table tr:last-child td { border-bottom: none; }
        h1 { color: #333; text-align: center; border-bottom: 2px solid #007bff; padding-bottom: 8px; font-size: 18px; margin: 10px 0; }
        h2 { color: #555; margin-top: 16px; font-size: 14px; }
        h3 { font-size: 12px; margin: 8px 0; }
        .summary-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 12px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px; border-radius: 6px; text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: bold; margin-bottom: 3px; }
        .stat-label { font-size: 0.85em; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; box-shadow: 0 1px 6px rgba(0,0,0,0.1); }
        th, td { padding: 4px 6px; text-align: left; border-bottom: 1px solid #ddd; font-size: 10px; }
        th { background-color: #007bff; color: white; font-weight: bold; white-space: nowrap; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e9ecef; }
        .proxy-yes { background-color: #d4edda; color: #155724; font-weight: bold; }
        .proxy-no { background-color: #f8d7da; color: #721c24; font-weight: bold; }
        .timestamp { text-align: center; color: #666; font-style: italic; margin-top: 12px; font-size: 10px; }
        .filter-input { width: 90%; padding: 3px; margin-top: 3px; border: 1px solid #ddd; border-radius: 3px; font-size: 9px; box-sizing: border-box; }
    </style>
    <script>
        function filterTable() {
            var table = document.getElementById("resultsTable");
            var tr = table.getElementsByTagName("tr");
            var inputs = document.getElementsByClassName("filter-input");
            var showInteresting = document.getElementById("showInterestingOnly") ? document.getElementById("showInterestingOnly").checked : false;
            
            // Loop through all table rows (skipping headers)
            // Start at 2 because row 0 is titles, row 1 is filter inputs
            for (var i = 2; i < tr.length; i++) {
                var display = true;
                
                // Check each column filter
                for (var j = 0; j < inputs.length; j++) {
                    var filterVal = inputs[j].value.toUpperCase();
                    var td = tr[i].getElementsByTagName("td")[j];
                    
                    if (filterVal && td) {
                        var txtValue = td.textContent || td.innerText;
                        if (txtValue.toUpperCase().indexOf(filterVal) == -1) {
                            display = false;
                            break;
                        }
                    }
                }
                
                // If still displaying, check "Show Interesting Only"
                if (display && showInteresting) {
                    var hasInterestingData = false;
                    var cells = tr[i].getElementsByTagName("td");
                    // Start checking from index 2 (Proxy Type) to end
                    for (var k = 2; k < cells.length; k++) {
                        var cellText = (cells[k].textContent || cells[k].innerText).trim();
                        if (cellText !== "-" && cellText !== "") {
                            hasInterestingData = true;
                            break;
                        }
                    }
                    if (!hasInterestingData) {
                        display = false;
                    }
                }
                
                tr[i].style.display = display ? "" : "none";
            }
        }
    </script>
</head>
<body>
    <div id="nav-ribbon">
        <a href="#summary" class="nav-btn">Summary</a>
        <a href="#distributions" class="nav-btn">Distributions</a>
        <a href="#detailed" class="nav-btn">Detailed Results</a>
    </div>

    <div class="container">
        <h1>IP Proxy Lookup Report</h1>""")
        
        if summary:
            html.append(f"""
        <h2 id="summary" class="section-anchor">Summary Statistics</h2>
        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-number">{summary['total_ips']}</div>
                <div class="stat-label">Total IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary['proxy_count']}</div>
                <div class="stat-label">Proxies Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary['proxy_percentage']:.1f}%</div>
                <div class="stat-label">Proxy Percentage</div>
            </div>
        </div>""")
            
            # Add detailed summary sections
            if any(k in summary for k in ['proxy_types', 'proxy_countries', 'proxy_domains', 'proxy_threats']):
                html.append("""
        <h2 id="distributions" class="section-anchor">Distributions</h2>
        <div class="distribution-wrapper">""")
                
                # Proxy Types
                if summary.get('proxy_types'):
                    html.append("""
            <div class="distribution-col">
                <h3>Proxy Types</h3>
                <table class="compact-table">
                    <thead><tr><th>Type</th><th style="text-align:right">Count</th></tr></thead>
                    <tbody>""")
                    for k, v in summary['proxy_types'].items():
                        html.append(f"<tr><td>{k}</td><td style='text-align:right'>{v}</td></tr>")
                    html.append("""
                    </tbody>
                </table>
            </div>""")

                # Countries
                if summary.get('proxy_countries'):
                    html.append("""
            <div class="distribution-col">
                <h3>Countries</h3>
                <table class="compact-table">
                    <thead><tr><th>Country</th><th style="text-align:right">Count</th></tr></thead>
                    <tbody>""")
                    for k, v in summary['proxy_countries'].items():
                        html.append(f"<tr><td>{k}</td><td style='text-align:right'>{v}</td></tr>")
                    html.append("""
                    </tbody>
                </table>
            </div>""")
                
                # Domains
                if summary.get('proxy_domains'):
                    html.append("""
            <div class="distribution-col">
                <h3>Domains</h3>
                <table class="compact-table">
                    <thead><tr><th>Domain</th><th style="text-align:right">Count</th></tr></thead>
                    <tbody>""")
                    for k, v in summary['proxy_domains'].items():
                        html.append(f"<tr><td>{k}</td><td style='text-align:right'>{v}</td></tr>")
                    html.append("""
                    </tbody>
                </table>
            </div>""")

                # Threats
                if summary.get('proxy_threats'):
                    html.append("""
            <div class="distribution-col">
                <h3>Threats</h3>
                <table class="compact-table">
                    <thead><tr><th>Threat</th><th style="text-align:right">Count</th></tr></thead>
                    <tbody>""")
                    for k, v in summary['proxy_threats'].items():
                        html.append(f"<tr><td>{k}</td><td style='text-align:right'>{v}</td></tr>")
                    html.append("""
                    </tbody>
                </table>
            </div>""")
                
                html.append("</div>")
        
        # Add results table
        html.append(f"""
        <h2 id="detailed" class="section-anchor">Detailed Results ({len(results)} IPs)</h2>
        <div style="margin-bottom: 10px;">
            <label><input type="checkbox" id="showInterestingOnly" onchange="filterTable()"> Show Interesting Only (rows with extra data)</label>
        </div>
        <table id="resultsTable">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Proxy Status</th>
                    <th>Proxy Type</th>
                    <th>Country</th>
                    <th>Region</th>
                    <th>City</th>
                    <th>ISP</th>
                    <th>Domain</th>
                    <th>Usage Type</th>
                    <th>ASN</th>
                    <th>Last Seen</th>
                    <th>Threat</th>
                    <th>Notes</th>
                </tr>
                <tr id="filterRow">
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter IP..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Status..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Type..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Country..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Region..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter City..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter ISP..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Domain..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Usage..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter ASN..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Last Seen..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Threat..."></th>
                    <th><input type="text" class="filter-input" onkeyup="filterTable()" placeholder="Filter Notes..."></th>
                </tr>
            </thead>
            <tbody>""")
        
        # Add table rows
        for result in results:
            proxy_class = "proxy-yes" if result.is_proxy else "proxy-no"
            proxy_status = "Yes" if result.is_proxy else "No"
            
            html.append(f"""
                <tr>
                    <td><strong>{result.ip}</strong></td>
                    <td class="{proxy_class}">{proxy_status}</td>
                    <td>{result.proxy_type or '-'}</td>
                    <td>{result.country_name or result.country_code or '-'}</td>
                    <td>{result.region or '-'}</td>
                    <td>{result.city or '-'}</td>
                    <td>{result.isp or '-'}</td>
                    <td>{result.domain or '-'}</td>
                    <td>{result.usage_type or '-'}</td>
                    <td>{result.asn or '-'}</td>
                    <td>{result.last_seen or '-'}</td>
                    <td>{result.threat or '-'}</td>
                    <td>{result.notes or '-'}</td>
                </tr>""")
        
        # HTML footer
        html.append(f"""
            </tbody>
        </table>
        
        <div class="timestamp">
            Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>""")
        
        return '\n'.join(html)
    
    def close(self):
        """Close database connections and cleanup resources."""
        if self.db:
            try:
                self.db.close()
                logging.info("Closed IP2Proxy BIN database")
            except Exception as e:
                logging.error(f"Error closing BIN database: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='IP Proxy Lookup Utility')
    parser.add_argument('ip', nargs='?', help='IP address to lookup')
    parser.add_argument('--file', '-f', help='File containing IP addresses (one per line)')
    parser.add_argument('--data-path', '-d', default='IP2PROXY-LITE-PX12', 
                       help='Path to IP2Proxy data directory')
    parser.add_argument('--use-csv', action='store_true',
                       help='Use CSV database instead of BIN (BIN is faster and used by default)')
    parser.add_argument('--summary', '-s', action='store_true',
                       help='Show summary statistics for batch lookups')
    parser.add_argument('--no-html', action='store_true',
                       help='Disable HTML report generation (HTML is generated by default)')
    parser.add_argument('--output-file', '-o', help='Output file for HTML results')
    parser.add_argument('--processes', '-p', type=int, default=None,
                       help='Number of processes for multiprocessing (default: auto-detect)')
    parser.add_argument('--chunk-size', '-g', type=int, default=None,
                       help='Chunk size for multiprocessing (default: auto-calculate)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        with ProxyLookup(args.data_path, use_csv=args.use_csv) as lookup:
            # Show which database mode is being used
            db_mode = "BIN (fast)" if lookup.use_bin else "CSV (slow)"
            print(f'Database mode: {db_mode}')

            if args.file:
                # Batch lookup from file
                with open(args.file, 'r') as f:
                    ip_addresses = [line.strip() for line in f if line.strip()]

                print(f'Items to process: {len(ip_addresses)}')

                # Get results using chunk-based multiprocessing
                results = lookup.batch_lookup(
                    ip_addresses,
                    num_processes=args.processes,
                    chunk_size=args.chunk_size
                )
                summary = lookup.get_proxy_summary(results)
                
                if not args.no_html:
                    # Generate HTML report (default behavior)
                    html_content = lookup.generate_html_report(results, summary)

                    if args.output_file:
                        # Write to specified output file
                        with open(args.output_file, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        print(f"HTML report saved to: {args.output_file}")
                    else:
                        # Write to default filename
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        output_file = f"proxy_report_{timestamp}.html"
                        with open(output_file, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        print(f"HTML report saved to: {output_file}")
                
                if args.summary:
                    # Display summary in console
                    print(f"\nProxy Detection Summary:")
                    print(f"Total IPs: {summary['total_ips']}")
                    print(f"Proxies detected: {summary['proxy_count']} ({summary['proxy_percentage']:.1f}%)")
                    
                    if summary['proxy_types']:
                        print(f"\nProxy Types:")
                        for ptype, count in summary['proxy_types'].items():
                            print(f"  {ptype}: {count}")
                    
                    if summary['proxy_countries']:
                        print(f"\nProxy Countries:")
                        for country, count in summary['proxy_countries'].items():
                            print(f"  {country}: {count}")
                    
                    if summary['proxy_domains']:
                        print(f"\nProxy Domains:")
                        for domain, count in summary['proxy_domains'].items():
                            print(f"  {domain}: {count}")
                    
                    if summary['proxy_last_seen']:
                        print(f"\nLast Seen Dates:")
                        for last_seen, count in summary['proxy_last_seen'].items():
                            print(f"  {last_seen}: {count}")
                    
                    if summary['proxy_threats']:
                        print(f"\nThreat Classifications:")
                        for threat, count in summary['proxy_threats'].items():
                            print(f"  {threat}: {count}")
                
                if args.no_html and not args.summary:
                    # Display individual results in console (only when HTML is disabled)
                    for result in results:
                        print(f"\nIP: {result.ip}")
                        print(f"  Proxy: {'Yes' if result.is_proxy else 'No'}")
                        if result.is_proxy:
                            print(f"  Type: {result.proxy_type}")
                            print(f"  Country: {result.country_name} ({result.country_code})")
                            print(f"  ISP: {result.isp}")
                            print(f"  Notes: {result.notes}")
            
            elif args.ip:
                # Single IP lookup
                result = lookup.lookup_proxy(args.ip)
                print(f"\nProxy Lookup for {result.ip}:")
                print(f"  Proxy: {'Yes' if result.is_proxy else 'No'}")
                if result.is_proxy:
                    print(f"  Type: {result.proxy_type}")
                    print(f"  Country: {result.country_name} ({result.country_code})")
                    print(f"  Region: {result.region}")
                    print(f"  City: {result.city}")
                    print(f"  ISP: {result.isp}")
                    print(f"  Domain: {result.domain}")
                    print(f"  Usage Type: {result.usage_type}")
                    print(f"  ASN: {result.asn}")
                    print(f"  AS Name: {result.as_name}")
                    print(f"  Last Seen: {result.last_seen}")
                    print(f"  Threat: {result.threat}")
                print(f"  Notes: {result.notes}")
            
            else:
                parser.print_help()
    
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
