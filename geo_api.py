#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# Version 3.0
# Date: 2025-08-12
# This module contains the get_geo_infoAPI function for IP geolocation via API

import json
import logging
import requests
# Define Result class locally to avoid circular import
class Result:
    def __init__(self, ip='', country='', city='', asn='', asn_org='', isp = '', host='', indicators=None, vt=None, vt_rep=None, is_proxy='', notes=None):
        self.ip = ip
        self.country = country
        self.city = city
        self.asn = asn
        self.asn_org = asn_org
        self.isp = isp
        self.host = host
        self.indicators = indicators
        self.vt = vt
        self.vt_rep = vt_rep
        self.is_proxy = is_proxy
        self.notes = notes  # Placeholder for any additional notes or comments


def get_geo_infoAPI(ip_address, result):
    """
    This works as a fallback when we don't find an ASN for an IP in the MaxM*nd ASN db
    Uses freeipapi.com to get geolocation information for an IP address
    
    Args:
        ip_address (str): The IP address to look up
        result (Result): Result object to populate with geolocation data
        
    Returns:
        Result: Updated result object with geolocation information
    """
    #esult = Result(ip=ip_address, country='', city='', asn='', asn_org='', isp='', host='', indicators='', vt='', vt_rep='')

    # try:
    #     url = f"http://ipwho.is/{ip_address}"
    #     response = requests.get(url)
    #     data = json.loads(response.content)
    #     if response.status_code == 200:
    #         connection_info = data.get("connection")
    #         print(f"connection_info: {data}")
    #         if not data.get("success") is False:
    #             if connection_info:
    #                 if data.get("country") is not None:
    #                     result.country = data.get("country")
    #                 if data.get("city") is not None:
    #                     result.city = data.get("city")
    #                 if data.get("asn") is not None:
    #                     result.asn = connection_info.get("asn")
    #                 if data.get("org") is not None:
    #                     result.asn_org = connection_info.get("org")
    #                 if data.get("domain") is not None:
    #                     result.host = connection_info.get("domain")
    #                 if data.get("isp") is not None:
    #                     result.isp = connection_info.get("isp")
    #                 if data.get("asn") is not None:
    #                     result.notes = check_asn_rep(f'{connection_info.get("asn")}')
    #         else:
    #             logging.exception(f'get_org_info API [error]:{data.get("message")}')

    #         #print(f"Fallback mapping for {ip_address}: asn: {result.asn} org: {result.asn_org}")
    # except Exception as e:
    #     logging.exception(f'get_org_info API [error]:{e}')

    try:
        url = f"https://free.freeipapi.com/api/json/{ip_address}"
        response = requests.get(url)
        data = json.loads(response.content)
        #print(f"connection_info: {data}")
        if response.status_code == 200:
            connection_info = data.get("connection")
            
            if connection_info:
                if data.get("countryName") is not None:
                    result.country = data.get("country")
                if data.get("city") is not None:
                    result.city = data.get("city")
                if data.get("asn") is not None:
                    result.asn = connection_info.get("asn")
                if data.get("org") is not None:
                    result.asn_org = connection_info.get("asnOrganization")
                if data.get("domain") is not None:
                    result.host = connection_info.get("domain")
                if data.get("isp") is not None:
                    result.isp = connection_info.get("isp")
                if data.get("asnOrganization") is not None:
                    result.asn_org = connection_info.get("asnOrganization")
                if data.get("isp") is not None:
                    result.isp = connection_info.get("isp")
                if data.get("isProxy") is not None:
                    result.is_proxy = connection_info.get("isProxy")
            else:
                logging.exception(f'GeoIP API [IP {ip_address}]: {data.get("message")}')

            #print(f"Fallback mapping for {ip_address}: asn: {result.asn} org: {result.asn_org}")
    except Exception as e:
        logging.exception(f'get_geo_infoAPI API [error]:{e}')

    return result
