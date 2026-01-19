#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# Version 3.0
# Date: 2025-08-12
# This module contains utility functions for IP address handling

import ipaddress
from netaddr import IPAddress


def is_private_ip(ip_address):
    """
    Check if an IP address is in a private IP range.
    
    Private IP ranges include:
    - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    - 127.0.0.0/8 (127.0.0.0 - 127.255.255.255) - Loopback
    - 169.254.0.0/16 (169.254.0.0 - 169.254.255.255) - Link-local
    - 0.0.0.0/8 (0.0.0.0 - 0.255.255.255) - Current network
    - 224.0.0.0/4 (224.0.0.0 - 239.255.255.255) - Multicast
    - 240.0.0.0/4 (240.0.0.0 - 255.255.255.255) - Reserved
    
    Args:
        ip_address (str): The IP address to check
        
    Returns:
        bool: True if the IP is private, False otherwise
    """
    try:
        # Parse the IP address
        ip = ipaddress.ip_address(ip_address)
        
        # Check if it's a private IP
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        
    except ValueError:
        # If the IP address is invalid, treat it as non-private
        # This allows the main processing to handle invalid IPs appropriately
        return False


def is_private_ip_netaddr(ip_address):
    """
    Alternative implementation using netaddr library for consistency with existing code.
    
    Args:
        ip_address (str): The IP address to check
        
    Returns:
        bool: True if the IP is private, False otherwise
    """
    try:
        ip = IPAddress(ip_address)
        
        # Check private ranges
        if ip.is_private():
            return True
            
        # Check loopback (127.0.0.0/8)
        if ip.is_loopback():
            return True
            
        # Check link-local (169.254.0.0/16)
        if ip.is_link_local():
            return True
            
        # Check multicast (224.0.0.0/4)
        if ip.is_multicast():
            return True
            
        # Check reserved (240.0.0.0/4)
        if ip.is_reserved():
            return True
            
        # Check current network (0.0.0.0/8)
        if ip.is_hostmask():
            return True
            
        return False
        
    except Exception:
        # If there's any error parsing the IP, treat it as non-private
        return False


def get_private_ip_reason(ip_address):
    """
    Get a human-readable reason why an IP is considered private.
    
    Args:
        ip_address (str): The IP address to check
        
    Returns:
        str: Reason why the IP is private, or empty string if not private
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        
        if ip.is_private:
            if ip.is_private:
                return "Private IP range"
        if ip.is_loopback:
            return "Loopback address"
        if ip.is_link_local:
            return "Link-local address"
        if ip.is_multicast:
            return "Multicast address"
        if ip.is_reserved:
            return "Reserved address"
            
        return ""
        
    except ValueError:
        return "Invalid IP address"


def filter_private_ips(ip_list, include_reason=False):
    """
    Filter a list of IPs to exclude private IPs.
    
    Args:
        ip_list (list): List of IP addresses to filter
        include_reason (bool): Whether to include reason for filtering
        
    Returns:
        tuple: (filtered_ips, filtered_out_ips_with_reasons)
    """
    filtered_ips = []
    filtered_out = []
    
    for ip in ip_list:
        if is_private_ip(ip):
            reason = get_private_ip_reason(ip) if include_reason else "Private IP"
            filtered_out.append((ip, reason))
        else:
            filtered_ips.append(ip)
    
    return filtered_ips, filtered_out
