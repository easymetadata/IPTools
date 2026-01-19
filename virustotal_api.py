#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# Version 3.0
# Date: 2025-08-12
# This module contains the vt_is_malicious_ip function for VirusTotal API lookups

import logging
import requests
import time


def vt_is_malicious_ip(ip_address, virustotal_api_key, vt_sleep_time=31):
    """
    This function checks the IP against the VirusTotal API
    
    Args:
        ip_address (str): The IP address to check
        virustotal_api_key (str): VirusTotal API key
        vt_sleep_time (int): Seconds to wait between requests to VirusTotal API
        
    Returns:
        str: Analysis results and reputation, or empty string if error
    """
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': virustotal_api_key
        }

        time.sleep(vt_sleep_time)

        response = requests.get(url, headers=headers)
        data = response.json()

        # lDetects = ['malicious','suspicious']

        if response.status_code == 200:
            if 'data' in data:
                attributes = data['data']['attributes']
                attrVtRep = attributes['reputation']
                if 'last_analysis_stats' in attributes:
                    stats = []
                    for val in attributes['last_analysis_stats']:
                        if attributes['last_analysis_stats'][val] > 0:
                            stats.append(f"{val}:{attributes['last_analysis_stats'][val]}")
                    # if any(map(lambda v: v in lDetects, stats)):
                    return ";".join(stats) + f",{attrVtRep}"
                else:
                    return ""  # No analysis data available
            else:
                return ""  # No data available for the given IP
        else:
            print(f"Error: {data['error']['message']}")
            return ""  # Error occurred while querying the API
    except Exception as err:
        logging.exception(err)
        print(err)
        return ""
