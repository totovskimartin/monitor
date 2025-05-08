"""
Uptime API endpoints for the new uptime chart implementation
This module uses uptime_utils to avoid circular imports
"""

from flask import Blueprint, jsonify, request
import logging
from api.uptime_utils import get_domain_uptime_data, refresh_domain_uptime_data

# Set up logging
logger = logging.getLogger(__name__)

# Create blueprint
uptime_api = Blueprint('uptime_api', __name__)

@uptime_api.route('/api/domains/<domain>/uptime', methods=['GET'])
def get_domain_uptime(domain):
    """
    Get uptime data for a domain
    
    Returns:
        JSON with uptime data including:
        - segments: List of status values for each time segment
        - percentage: Overall uptime percentage
        - is_new_domain: Whether this is a newly added domain
        - first_check: Timestamp of first check
        - last_check: Timestamp of last check
    """
    try:
        # Get timeframe from query parameter (default to 12 hours)
        timeframe_hours = request.args.get('timeframe', '12')
        try:
            timeframe_hours = int(timeframe_hours)
            if timeframe_hours not in [12, 24, 168]:  # 12h, 24h, 7d
                timeframe_hours = 12
        except ValueError:
            timeframe_hours = 12
            
        # Get uptime data using the utility function
        uptime_data = get_domain_uptime_data(domain, timeframe_hours)
        
        if uptime_data:
            # Return the data
            return jsonify({
                'success': True,
                **uptime_data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to get uptime data'
            }), 500
    
    except Exception as e:
        logger.error(f"Error getting uptime data for {domain}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error getting uptime data: {str(e)}"
        }), 500

@uptime_api.route('/api/domains/<domain>/uptime/refresh', methods=['POST'])
def refresh_domain_uptime(domain):
    """
    Refresh uptime data for a domain
    
    Returns:
        JSON with refreshed uptime data
    """
    try:
        # Refresh uptime data using the utility function
        uptime_data = refresh_domain_uptime_data(domain)
        
        if uptime_data:
            # Return the data
            return jsonify({
                'success': True,
                **uptime_data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to refresh uptime data'
            }), 500
    
    except Exception as e:
        logger.error(f"Error refreshing uptime data for {domain}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error refreshing uptime data: {str(e)}"
        }), 500
