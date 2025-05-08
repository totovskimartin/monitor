"""
Utility functions for uptime monitoring
This module avoids circular imports by providing standalone functions
"""

from datetime import datetime, timedelta
import logging
import database as db

# Set up logging
logger = logging.getLogger(__name__)

def get_domain_uptime_data(domain, timeframe_hours=12):
    """
    Get uptime data for a domain
    
    Args:
        domain: Domain name
        timeframe_hours: Number of hours to look back
        
    Returns:
        Dictionary with uptime data
    """
    try:
        # Get ping history for the domain
        ping_history = db.get_ping_history(domain, hours=timeframe_hours)
        
        # Calculate uptime percentage
        uptime_percentage = db.calculate_uptime_percentage(domain, hours=timeframe_hours)
        if uptime_percentage is not None:
            uptime_percentage = round(uptime_percentage, 1)
        else:
            uptime_percentage = 0
            
        # Determine if this is a new domain (less than 3 checks)
        is_new_domain = len(ping_history) < 3
        
        # Get current ping status
        current_status = "unknown"
        if ping_history and len(ping_history) > 0:
            # Sort by timestamp to get the most recent check
            sorted_history = sorted(ping_history, key=lambda x: x.get('checked_at', 0) or 0)
            if sorted_history:
                current_status = sorted_history[-1].get('status', 'unknown')
        
        # Create uptime segments
        segments = []
        
        # For new domains, only show current status
        if is_new_domain:
            segments = ['unknown'] * (timeframe_hours - 1) + [current_status]
        else:
            # Group history into hourly segments
            current_time = datetime.now()
            
            for i in range(timeframe_hours):
                segment_start = current_time - timedelta(hours=timeframe_hours-i)
                segment_end = current_time - timedelta(hours=timeframe_hours-i-1)
                
                # Find all checks in this segment
                segment_checks = [
                    check for check in ping_history
                    if check.get('checked_at') and
                    segment_start <= datetime.fromtimestamp(check.get('checked_at')) < segment_end
                ]
                
                if segment_checks:
                    # If any check is down, the segment is down
                    if any(check.get('status') == 'down' for check in segment_checks):
                        segments.append('down')
                    else:
                        segments.append('up')
                else:
                    # For the most recent segment, use current status if no data
                    if i == timeframe_hours - 1:
                        segments.append(current_status)
                    else:
                        segments.append('unknown')
        
        # Get first and last check timestamps
        first_check = None
        last_check = None
        
        if ping_history:
            # Sort by timestamp
            sorted_history = sorted(ping_history, key=lambda x: x.get('checked_at', 0) or 0)
            if sorted_history:
                first_check = sorted_history[0].get('checked_at')
                last_check = sorted_history[-1].get('checked_at')
        
        # Return the data
        return {
            'domain': domain,
            'segments': segments,
            'percentage': uptime_percentage,
            'is_new_domain': is_new_domain,
            'first_check': first_check,
            'last_check': last_check,
            'timeframe_hours': timeframe_hours
        }
    
    except Exception as e:
        logger.error(f"Error getting uptime data for {domain}: {str(e)}")
        return None

def refresh_domain_uptime_data(domain):
    """
    Refresh uptime data for a domain
    
    Args:
        domain: Domain name
        
    Returns:
        Dictionary with uptime data
    """
    try:
        # Clear ping cache for this domain
        db.clear_cache(f"ping_{domain}")
        
        # Use the database module to perform a ping check
        ping_status = db.get_ping_status(domain, force_refresh=True)
        
        # Extract the status from the ping result
        if ping_status and hasattr(ping_status, 'status'):
            current_status = ping_status.status
        else:
            current_status = 'unknown'
        
        # Get ping history for the domain (12 hours by default)
        ping_history = db.get_ping_history(domain, hours=12)
        
        # Calculate uptime percentage
        uptime_percentage = db.calculate_uptime_percentage(domain, hours=12)
        if uptime_percentage is not None:
            uptime_percentage = round(uptime_percentage, 1)
        else:
            uptime_percentage = 0
            
        # Determine if this is a new domain (less than 3 checks)
        is_new_domain = len(ping_history) < 3
        
        # Create uptime segments
        segments = []
        
        # For new domains, only show current status
        if is_new_domain:
            segments = ['unknown'] * 11 + [current_status]
        else:
            # Group history into hourly segments
            current_time = datetime.now()
            
            for i in range(12):  # Always use 12 hours for consistency
                segment_start = current_time - timedelta(hours=12-i)
                segment_end = current_time - timedelta(hours=12-i-1)
                
                # Find all checks in this segment
                segment_checks = [
                    check for check in ping_history
                    if check.get('checked_at') and
                    segment_start <= datetime.fromtimestamp(check.get('checked_at')) < segment_end
                ]
                
                if segment_checks:
                    # If any check is down, the segment is down
                    if any(check.get('status') == 'down' for check in segment_checks):
                        segments.append('down')
                    else:
                        segments.append('up')
                else:
                    # For the most recent segment, use current status if no data
                    if i == 11:  # Last segment
                        segments.append(current_status)
                    else:
                        segments.append('unknown')
        
        # Return the data
        return {
            'domain': domain,
            'segments': segments,
            'percentage': uptime_percentage,
            'is_new_domain': is_new_domain,
            'timeframe_hours': 12
        }
    
    except Exception as e:
        logger.error(f"Error refreshing uptime data for {domain}: {str(e)}")
        return None
