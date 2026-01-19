#!/usr/bin/python
"""
Pivot table utilities for IP enrichment results.
Provides functions to create pivot tables from IP enrichment data.
"""

import pandas as pd
import logging


def create_pivot_table(df):
    """
    Create a pivot table view grouped by indicators and IPs.
    
    Args:
        df: DataFrame with IP enrichment results
        
    Returns:
        pivot_df: Pivoted DataFrame
    """
    try:
        # Filter out rows where indicators is empty/None
        df_with_indicators = df[df['indicators'].notna() & (df['indicators'] != '')].copy()
        
        if df_with_indicators.empty:
            print("No threat indicators found to create pivot table.")
            return None
        
        # Split indicators by ' | ' to get individual threat types
        df_with_indicators['threat_types'] = df_with_indicators['indicators'].str.split(' | ')
        
        # Explode the threat types to create separate rows for each indicator
        df_exploded = df_with_indicators.explode('threat_types')
        
        # Clean up threat type names (remove whitespace and common suffixes)
        df_exploded['threat_types'] = df_exploded['threat_types'].str.strip().str.replace(' (cidr)', '', regex=False)
        
        # Create pivot table: threat types as columns, IPs as index
        pivot_df = df_exploded.pivot_table(
            index='ip',
            columns='threat_types',
            values='country',  # Use country as the value (could be any non-null column)
            aggfunc='count',  # Count occurrences
            fill_value=0
        )
        
        # Add summary columns
        pivot_df['total_threats'] = pivot_df.sum(axis=1)
        pivot_df['unique_threat_types'] = (pivot_df > 0).sum(axis=1)
        
        # Sort by total threats (descending)
        pivot_df = pivot_df.sort_values('total_threats', ascending=False)
        
        return pivot_df
        
    except Exception as e:
        logging.error(f"Error creating pivot table: {e}")
        print(f"Error creating pivot table: {e}")
        return None


def create_threat_type_pivot_table(df):
    """
    Create a pivot table view grouped by threat types and counting IPs.
    This is the reverse of the main pivot table - shows threat types as rows and IP counts as values.
    
    Args:
        df: DataFrame with IP enrichment results
        
    Returns:
        threat_pivot_df: Pivoted DataFrame with threat types as index
    """
    try:
        # Filter out rows where indicators is empty/None
        df_with_indicators = df[df['indicators'].notna() & (df['indicators'] != '')].copy()
        
        if df_with_indicators.empty:
            print("No threat indicators found to create threat type pivot table.")
            return None
        
        # Split indicators by ' | ' to get individual threat types
        df_with_indicators['threat_types'] = df_with_indicators['indicators'].str.split(' | ')
        
        # Explode the threat types to create separate rows for each indicator
        df_exploded = df_with_indicators.explode('threat_types')
        
        # Clean up threat type names (remove whitespace and common suffixes)
        df_exploded['threat_types'] = df_exploded['threat_types'].str.strip().str.replace(' (cidr)', '', regex=False)
        
        # Create pivot table: threat types as index, count of IPs as values
        threat_pivot_df = df_exploded.groupby('threat_types').agg({
            'ip': 'count',  # Count unique IPs for each threat type
            'country': 'nunique'  # Count unique countries for each threat type
        }).rename(columns={
            'ip': 'ip_count',
            'country': 'country_count'
        })
        
        # Add percentage of total threats
        total_threats = threat_pivot_df['ip_count'].sum()
        threat_pivot_df['percentage'] = (threat_pivot_df['ip_count'] / total_threats * 100).round(2)
        
        # Sort by IP count (descending)
        threat_pivot_df = threat_pivot_df.sort_values('ip_count', ascending=False)
        
        return threat_pivot_df
        
    except Exception as e:
        logging.error(f"Error creating threat type pivot table: {e}")
        print(f"Error creating threat type pivot table: {e}")
        return None


def get_pivot_summary_stats(pivot_df):
    """
    Get summary statistics for a pivot table.
    
    Args:
        pivot_df: Pivoted DataFrame
        
    Returns:
        dict: Dictionary containing summary statistics
    """
    if pivot_df is None or pivot_df.empty:
        return None
    
    try:
        total_ips_with_threats = len(pivot_df)
        total_threat_occurrences = pivot_df['total_threats'].sum()
        avg_threats_per_ip = total_threat_occurrences / total_ips_with_threats if total_ips_with_threats > 0 else 0
        
        return {
            'total_ips_with_threats': total_ips_with_threats,
            'total_threat_occurrences': total_threat_occurrences,
            'avg_threats_per_ip': avg_threats_per_ip
        }
    except Exception as e:
        logging.error(f"Error calculating pivot summary stats: {e}")
        return None


def get_threat_type_summary_stats(threat_pivot_df):
    """
    Get summary statistics for a threat type pivot table.
    
    Args:
        threat_pivot_df: Threat type pivoted DataFrame
        
    Returns:
        dict: Dictionary containing summary statistics
    """
    if threat_pivot_df is None or threat_pivot_df.empty:
        return None
    
    try:
        total_threat_types = len(threat_pivot_df)
        total_ips_affected = threat_pivot_df['ip_count'].sum()
        avg_ips_per_threat_type = total_ips_affected / total_threat_types if total_threat_types > 0 else 0
        
        return {
            'total_threat_types': total_threat_types,
            'total_ips_affected': total_ips_affected,
            'avg_ips_per_threat_type': avg_ips_per_threat_type
        }
    except Exception as e:
        logging.error(f"Error calculating threat type summary stats: {e}")
        return None


def print_pivot_summary(pivot_df):
    """
    Print a formatted summary of pivot table statistics.
    
    Args:
        pivot_df: Pivoted DataFrame
    """
    stats = get_pivot_summary_stats(pivot_df)
    if stats:
        print(f"\nSummary:")
        print(f"  - IPs with threats: {stats['total_ips_with_threats']}")
        print(f"  - Total threat occurrences: {stats['total_threat_occurrences']}")
        print(f"  - Average threats per IP: {stats['avg_threats_per_ip']:.2f}")
    else:
        print("No summary statistics available.")


def print_threat_type_summary(threat_pivot_df):
    """
    Print a formatted summary of threat type pivot table statistics.
    
    Args:
        threat_pivot_df: Threat type pivoted DataFrame
    """
    stats = get_threat_type_summary_stats(threat_pivot_df)
    if stats:
        print(f"\nThreat Type Summary:")
        print(f"  - Total threat types: {stats['total_threat_types']}")
        print(f"  - Total IPs affected: {stats['total_ips_affected']}")
        print(f"  - Average IPs per threat type: {stats['avg_ips_per_threat_type']:.2f}")
    else:
        print("No threat type summary statistics available.")
