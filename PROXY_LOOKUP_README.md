# IP2Proxy Lookup Utility

A comprehensive IP proxy lookup utility that integrates with the IP2Proxy LITE PX9 database to detect and analyze proxy IP addresses. This utility is designed to work seamlessly with the existing ipEnrich5 project structure.

## Features

- **Dual Database Support**: Works with both IP2Proxy BIN databases and CSV files
- **Efficient Lookup**: Fast binary search algorithm for CSV-based lookups
- **Batch Processing**: Process multiple IP addresses efficiently
- **Comprehensive Data**: Extract detailed proxy information including type, location, ISP, and threat data
- **Integration Ready**: Designed to integrate with existing ipEnrich5 workflows
- **Command Line Interface**: Full CLI support for standalone usage

## Installation

### Prerequisites

- Python 3.7+
- IP2Proxy Python library (optional, for BIN database support)

### Install Dependencies

```bash
pip install IP2Proxy
```

The utility will work without the IP2Proxy library, falling back to CSV-based lookups.

## Usage

### Command Line Interface

#### Single IP Lookup

```bash
python proxy_lookup.py 8.8.8.8
```

#### Batch Lookup from File

```bash
python proxy_lookup.py --file ip_list.txt
```

#### Summary Statistics

```bash
python proxy_lookup.py --file ip_list.txt --summary
```

#### HTML Report Generation

```bash
# Generate HTML report with default filename
python proxy_lookup.py --file ip_list.txt --html

# Generate HTML report with custom filename
python proxy_lookup.py --file ip_list.txt --html --output-file my_report.html

# Generate both HTML report and console summary
python proxy_lookup.py --file ip_list.txt --html --summary
```

#### Verbose Output

```bash
python proxy_lookup.py 8.8.8.8 --verbose
```

#### Use BIN Database (if available)

```bash
python proxy_lookup.py 8.8.8.8 --use-bin
```

### Command Line Options

- `ip`: Single IP address to lookup
- `--file, -f`: File containing IP addresses (one per line)
- `--data-path, -d`: Path to IP2Proxy data directory (default: IP2PROXY-LITE-PX9)
- `--use-bin`: Use BIN database if available
- `--summary, -s`: Show summary statistics for batch lookups
- `--html`: Generate HTML table output
- `--output-file, -o`: Output file for HTML results
- `--verbose, -v`: Verbose output with debug information

### Python API Usage

#### Basic Usage

```python
from proxy_lookup import ProxyLookup

# Initialize lookup utility
with ProxyLookup() as lookup:
    # Single IP lookup
    result = lookup.lookup_proxy("8.8.8.8")
    
    if result.is_proxy:
        print(f"Proxy detected: {result.proxy_type}")
        print(f"Country: {result.country_name}")
        print(f"ISP: {result.isp}")
```

#### Batch Processing

```python
from proxy_lookup import ProxyLookup

ip_addresses = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

with ProxyLookup() as lookup:
    # Batch lookup
    results = lookup.batch_lookup(ip_addresses)
    
    # Get summary statistics
    summary = lookup.get_proxy_summary(ip_addresses)
    
    print(f"Found {summary['proxy_count']} proxies out of {summary['total_ips']} IPs")
    
    # Enhanced summary includes additional columns
    if summary['proxy_domains']:
        print(f"Proxy domains found: {len(summary['proxy_domains'])}")
    if summary['proxy_threats']:
        print(f"Threat classifications: {len(summary['proxy_threats'])}")
```

#### HTML Report Generation

```python
from proxy_lookup import ProxyLookup

ip_addresses = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

with ProxyLookup() as lookup:
    # Get results and summary
    results = lookup.batch_lookup(ip_addresses)
    summary = lookup.get_proxy_summary(ip_addresses)
    
    # Generate HTML report
    html_content = lookup.generate_html_report(results, summary)
    
    # Save to file
    with open('proxy_report.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("HTML report generated successfully!")
```

#### Integration with Existing Project

```python
from proxy_lookup import ProxyLookup

def enrich_ip_with_proxy_info(ip_address, existing_result):
    """Enrich existing IP enrichment result with proxy information."""
    
    with ProxyLookup() as lookup:
        proxy_result = lookup.lookup_proxy(ip_address)
        
        if proxy_result.is_proxy:
            # Add proxy information to threat indicators
            if not existing_result.indicators:
                existing_result.indicators = []
            
            existing_result.indicators.append({
                'type': 'proxy',
                'proxy_type': proxy_result.proxy_type,
                'country': proxy_result.country_code,
                'isp': proxy_result.isp,
                'source': 'IP2Proxy LITE PX9'
            })
            
            existing_result.is_proxy = 'Yes'
            existing_result.notes = f"Proxy detected: {proxy_result.proxy_type}"
    
    return existing_result
```

## HTML Report Generation

The utility can generate professional HTML reports with the following features:

- **Responsive Design**: Modern, mobile-friendly layout
- **Summary Statistics**: Visual cards showing key metrics
- **Detailed Results Table**: Comprehensive data in tabular format
- **Color Coding**: Proxy status indicators (green for proxies, red for clean IPs)
- **Interactive Elements**: Hover effects and responsive grid layouts
- **Professional Styling**: Clean, modern design suitable for reports

### HTML Output Options

- **Default Filename**: Automatically generates timestamped filename (e.g., `proxy_report_20250127_143022.html`)
- **Custom Filename**: Specify output file with `--output-file` option
- **Combined Output**: Use `--html --summary` for both HTML report and console output

## Enhanced Summary Statistics

The `get_proxy_summary()` method provides comprehensive statistics including:

- **Basic Statistics**: Total IPs, proxy count, and percentage
- **Proxy Types**: Breakdown of proxy types (VPN, TOR, DCH, etc.)
- **Geographic Distribution**: Countries where proxies are located
- **Domain Analysis**: Associated domains for proxy IPs
- **Temporal Data**: Last seen dates for proxy activity
- **Threat Classification**: Threat levels and classifications

### Summary Output Example

```bash
python proxy_lookup.py --file ip_list.txt --summary
```

Output includes:
```
Proxy Detection Summary:
Total IPs: 100
Proxies detected: 15 (15.0%)

Proxy Types:
  VPN: 8
  TOR: 4
  DCH: 3

Proxy Countries:
  US: 6
  NL: 4
  DE: 3
  RU: 2

Proxy Domains:
  example.com: 5
  proxy.net: 3
  vpn.org: 2

Last Seen Dates:
  2025-01-15: 8
  2025-01-14: 4
  2025-01-13: 3

Threat Classifications:
  Low: 10
  Medium: 3
  High: 2
```

## Data Structure

### ProxyResult Class

The utility returns `ProxyResult` objects with the following attributes:

- `ip`: IP address
- `is_proxy`: Boolean indicating if IP is a proxy
- `proxy_type`: Type of proxy (e.g., VPN, TOR, DCH, etc.)
- `country_code`: Two-letter country code
- `country_name`: Full country name
- `region`: Region/state name
- `city`: City name
- `isp`: Internet Service Provider
- `domain`: Associated domain
- `usage_type`: Usage type classification
- `asn`: Autonomous System Number
- `as_name`: Autonomous System Name
- `last_seen`: Last seen timestamp
- `threat`: Threat classification
- `provider`: Proxy provider name
- `fraud_score`: Fraud risk score
- `notes`: Additional notes or error messages

### CSV Data Format

The utility expects IP2Proxy LITE PX9 CSV format with 14 columns:

1. Start IP (long integer)
2. End IP (long integer)
3. Proxy Type
4. Country Code
5. Country Name
6. Region
7. City
8. ISP
9. Domain
10. Usage Type
11. ASN
12. AS Name
13. Last Seen
14. Threat

## Database Support

### BIN Database (Recommended)

- Faster lookup performance
- Lower memory usage
- Requires IP2Proxy library
- Automatically detected if available

### CSV Database (Fallback)

- Works with standard CSV files
- Higher memory usage for large datasets
- Slower lookup performance
- No additional dependencies required

## Performance Considerations

- **CSV Lookups**: Linear search through ranges, suitable for small to medium datasets
- **BIN Lookups**: Optimized binary search, suitable for large datasets
- **Memory Usage**: CSV mode loads entire file into memory, BIN mode uses minimal memory
- **Batch Processing**: Efficient for processing multiple IPs sequentially

## Error Handling

The utility includes comprehensive error handling:

- Invalid IP addresses
- Missing or corrupted data files
- Database connection issues
- Malformed CSV data

All errors are logged and returned in the `notes` field of the result object.

## Testing

Run the test suite to verify functionality:

```bash
python test_proxy_lookup.py
```

The test suite covers:
- Single IP lookups
- Batch processing
- Summary statistics
- Integration patterns

## Integration with ipEnrich5

The proxy lookup utility is designed to integrate seamlessly with the existing ipEnrich5 project:

1. **Import the module**: `from proxy_lookup import ProxyLookup`
2. **Use in enrichment workflow**: Call `lookup_proxy()` during IP processing
3. **Add to threat indicators**: Include proxy information in threat feed matching
4. **Enhance reporting**: Include proxy detection in final reports

## License

This utility is part of the ipEnrich5 project and follows the same licensing terms.

## Support

For issues or questions:
1. Check the test suite for usage examples
2. Review the logging output for error details
3. Verify data file integrity and format
4. Ensure proper file permissions and paths

## Future Enhancements

- Caching for frequently accessed IPs
- Support for additional proxy databases
- Real-time threat feed integration
- Machine learning-based proxy detection
- API endpoint for web service integration
