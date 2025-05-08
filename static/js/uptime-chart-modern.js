/**
 * Modern Uptime Chart - Dashboard Implementation
 * A clean, reliable visualization of domain uptime
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all uptime charts
    initializeUptimeCharts();
});

/**
 * Initialize all uptime charts on the page
 */
function initializeUptimeCharts() {
    // Find all uptime chart containers
    const charts = document.querySelectorAll('.uptime-chart-modern');
    
    // Initialize each chart
    charts.forEach(chart => {
        // Get domain name from data attribute
        const domain = chart.dataset.domain;
        
        // Add event listeners for tooltips
        setupTooltips(chart);
        
        // If the chart is empty or has only unknown segments, try to fetch data
        const segments = chart.querySelectorAll('.uptime-segment-modern');
        const hasData = Array.from(segments).some(segment => 
            !segment.classList.contains('uptime-unknown-modern')
        );
        
        if (!hasData && domain) {
            fetchUptimeData(domain, chart);
        }
    });
}

/**
 * Set up tooltips for uptime chart segments
 * @param {HTMLElement} chart - The uptime chart element
 */
function setupTooltips(chart) {
    const segments = chart.querySelectorAll('.uptime-segment-modern');
    
    segments.forEach((segment, index) => {
        // Calculate hours ago (12 segments, rightmost is most recent)
        const hoursAgo = 11 - index;
        const status = segment.classList.contains('uptime-up-modern') ? 'Up' :
                      segment.classList.contains('uptime-down-modern') ? 'Down' : 'Unknown';
        
        // Create or update tooltip
        let tooltip = segment.querySelector('.uptime-tooltip-modern');
        if (!tooltip) {
            tooltip = document.createElement('span');
            tooltip.className = 'uptime-tooltip-modern';
            segment.appendChild(tooltip);
        }
        
        // Set tooltip text
        tooltip.textContent = `${status} - ${hoursAgo} hour${hoursAgo !== 1 ? 's' : ''} ago`;
    });
}

/**
 * Fetch uptime data for a domain
 * @param {string} domain - The domain name
 * @param {HTMLElement} chart - The chart element to update
 */
function fetchUptimeData(domain, chart) {
    // Show loading state
    chart.style.opacity = '0.6';
    
    // Fetch data from API
    fetch(`/api/domains/${domain}/uptime?timeframe=12`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateUptimeChart(chart, data.segments, data.percentage);
            }
            chart.style.opacity = '1';
        })
        .catch(error => {
            console.error('Error fetching uptime data:', error);
            chart.style.opacity = '1';
        });
}

/**
 * Update an uptime chart with new data
 * @param {HTMLElement} chart - The chart element to update
 * @param {Array} segments - Array of segment statuses ('up', 'down', 'unknown')
 * @param {number} percentage - Uptime percentage
 */
function updateUptimeChart(chart, segments, percentage) {
    // Clear existing segments
    chart.innerHTML = '';
    
    // Ensure we always have exactly 12 segments
    let normalizedSegments = segments;
    if (!segments || segments.length === 0) {
        // If no segments provided, create 12 unknown segments
        normalizedSegments = Array(12).fill('unknown');
    } else if (segments.length < 12) {
        // If fewer than 12 segments, pad with unknown at the beginning
        normalizedSegments = Array(12 - segments.length).fill('unknown').concat(segments);
    } else if (segments.length > 12) {
        // If more than 12 segments, take only the last 12
        normalizedSegments = segments.slice(segments.length - 12);
    }
    
    // Create segments
    normalizedSegments.forEach((status, index) => {
        const segment = document.createElement('div');
        segment.className = `uptime-segment-modern uptime-${status}-modern`;
        
        // Add tooltip
        const tooltip = document.createElement('span');
        tooltip.className = 'uptime-tooltip-modern';
        const hoursAgo = 11 - index;
        tooltip.textContent = `${status.charAt(0).toUpperCase() + status.slice(1)} - ${hoursAgo} hour${hoursAgo !== 1 ? 's' : ''} ago`;
        segment.appendChild(tooltip);
        
        chart.appendChild(segment);
    });
    
    // Update percentage if container exists
    const container = chart.closest('.uptime-container');
    if (container) {
        // Find or create percentage element
        let percentageElement = container.querySelector('.uptime-percentage-modern');
        if (!percentageElement) {
            percentageElement = document.createElement('div');
            container.appendChild(percentageElement);
        }
        
        // Update content and classes
        percentageElement.textContent = `${percentage}%`;
        percentageElement.className = 'uptime-percentage-modern';
        
        if (percentage >= 99) {
            percentageElement.classList.add('uptime-high-modern');
        } else if (percentage >= 90) {
            percentageElement.classList.add('uptime-medium-modern');
        } else {
            percentageElement.classList.add('uptime-low-modern');
        }
    }
}

/**
 * Refresh uptime data for all domains
 */
function refreshAllUptimeCharts() {
    const charts = document.querySelectorAll('.uptime-chart-modern');
    
    charts.forEach(chart => {
        const domain = chart.dataset.domain;
        if (domain) {
            fetchUptimeData(domain, chart);
        }
    });
}

// Make functions available globally
window.uptimeChartModern = {
    initialize: initializeUptimeCharts,
    refresh: refreshAllUptimeCharts,
    update: updateUptimeChart
};
