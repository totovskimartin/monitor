/**
 * Modern Uptime Chart - New Implementation
 * A clean, reliable visualization of domain uptime
 */

class UptimeChart {
  /**
   * Create a new uptime chart
   * @param {Object} options - Configuration options
   * @param {string} options.selector - CSS selector for the container element
   * @param {number} options.segments - Number of segments to display (default: 12)
   * @param {string} options.timeUnit - Time unit for labels (default: 'hour')
   * @param {boolean} options.showPercentage - Whether to show the percentage (default: true)
   */
  constructor(options) {
    this.options = Object.assign({
      selector: '.uptime-visualization',
      segments: 12,
      timeUnit: 'hour',
      showPercentage: true
    }, options);

    this.containers = document.querySelectorAll(this.options.selector);
    if (this.containers.length === 0) {
      console.warn(`No elements found matching selector: ${this.options.selector}`);
      return;
    }

    this.init();
  }

  /**
   * Initialize the uptime charts
   */
  init() {
    this.containers.forEach(container => {
      // Get domain data from container attributes
      const domain = container.dataset.domain;
      const isNewDomain = container.dataset.isNewDomain === 'true';
      
      // Create chart elements
      this.createChartElements(container, domain, isNewDomain);
      
      // Fetch initial data
      this.fetchUptimeData(domain)
        .then(data => {
          this.updateChart(container, data);
        })
        .catch(error => {
          console.error(`Error fetching uptime data for ${domain}:`, error);
          this.showErrorState(container);
        });
    });

    // Set up refresh button event listeners
    document.querySelectorAll('[data-action="refresh-uptime"]').forEach(button => {
      button.addEventListener('click', event => {
        const domain = button.dataset.domain;
        const container = document.querySelector(`.uptime-visualization[data-domain="${domain}"]`);
        
        if (container) {
          this.refreshUptimeData(container, domain);
        }
      });
    });
  }

  /**
   * Create the chart elements
   * @param {HTMLElement} container - The container element
   * @param {string} domain - The domain name
   * @param {boolean} isNewDomain - Whether this is a newly added domain
   */
  createChartElements(container, domain, isNewDomain) {
    // Clear the container
    container.innerHTML = '';
    
    // Create the chart container
    const chartContainer = document.createElement('div');
    chartContainer.className = 'uptime-chart-container';
    
    // Create the chart
    const chart = document.createElement('div');
    chart.className = 'uptime-chart-new';
    chart.dataset.domain = domain;
    
    // Create the segments
    for (let i = 0; i < this.options.segments; i++) {
      const segment = document.createElement('div');
      segment.className = 'uptime-bar uptime-status-unknown';
      segment.dataset.index = i;
      
      // Create tooltip
      const tooltip = document.createElement('div');
      tooltip.className = 'uptime-tooltip';
      tooltip.textContent = 'No data';
      
      segment.appendChild(tooltip);
      chart.appendChild(segment);
    }
    
    // Create time axis
    const timeAxis = document.createElement('div');
    timeAxis.className = 'uptime-time-axis';
    
    // Add start and end labels
    const startLabel = document.createElement('div');
    startLabel.className = 'uptime-time-label';
    startLabel.textContent = `${this.options.segments}${this.options.timeUnit}s ago`;
    
    const endLabel = document.createElement('div');
    endLabel.className = 'uptime-time-label';
    endLabel.textContent = 'Now';
    
    timeAxis.appendChild(startLabel);
    timeAxis.appendChild(endLabel);
    
    // Create percentage element if needed
    let percentageElement = null;
    if (this.options.showPercentage) {
      percentageElement = document.createElement('div');
      percentageElement.className = 'uptime-percentage-new uptime-percentage-high';
      percentageElement.textContent = 'N/A';
      container.appendChild(percentageElement);
    }
    
    // Add new domain indicator if needed
    if (isNewDomain) {
      const newIndicator = document.createElement('div');
      newIndicator.className = 'uptime-new-domain';
      newIndicator.textContent = 'New';
      chart.appendChild(newIndicator);
    }
    
    // Assemble the chart
    chartContainer.appendChild(chart);
    chartContainer.appendChild(timeAxis);
    container.appendChild(chartContainer);
  }

  /**
   * Fetch uptime data for a domain
   * @param {string} domain - The domain name
   * @returns {Promise<Object>} - The uptime data
   */
  fetchUptimeData(domain) {
    return fetch(`/api/domains/${domain}/uptime`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (!data.success) {
          throw new Error(data.error || 'Unknown error');
        }
        return data;
      });
  }

  /**
   * Update the chart with new data
   * @param {HTMLElement} container - The container element
   * @param {Object} data - The uptime data
   */
  updateChart(container, data) {
    const chart = container.querySelector('.uptime-chart-new');
    const segments = chart.querySelectorAll('.uptime-bar');
    const percentageElement = container.querySelector('.uptime-percentage-new');
    
    // Handle the case of a new domain with limited history
    const isNewDomain = data.is_new_domain || false;
    
    // Update segments
    if (data.segments && data.segments.length > 0) {
      // Normalize segments to match our display count
      let normalizedSegments = this.normalizeSegments(data.segments, isNewDomain);
      
      // Update each segment
      segments.forEach((segment, index) => {
        const status = normalizedSegments[index] || 'unknown';
        
        // Update class
        segment.className = `uptime-bar uptime-status-${status}`;
        
        // Update tooltip
        const tooltip = segment.querySelector('.uptime-tooltip');
        if (tooltip) {
          const timeAgo = this.options.segments - index;
          tooltip.textContent = `${status.charAt(0).toUpperCase() + status.slice(1)} - ${timeAgo} ${this.options.timeUnit}(s) ago`;
        }
      });
    }
    
    // Update percentage
    if (percentageElement && data.percentage !== undefined) {
      percentageElement.textContent = `${data.percentage}%`;
      
      // Update class based on percentage
      percentageElement.className = 'uptime-percentage-new';
      if (data.percentage >= 99) {
        percentageElement.classList.add('uptime-percentage-high');
      } else if (data.percentage >= 90) {
        percentageElement.classList.add('uptime-percentage-medium');
      } else {
        percentageElement.classList.add('uptime-percentage-low');
      }
    }
  }

  /**
   * Normalize segments to match our display count
   * @param {Array<string>} segments - The segments from the API
   * @param {boolean} isNewDomain - Whether this is a newly added domain
   * @returns {Array<string>} - Normalized segments
   */
  normalizeSegments(segments, isNewDomain) {
    // For new domains, we only want to show the current status
    if (isNewDomain) {
      const currentStatus = segments[segments.length - 1] || 'unknown';
      return Array(this.options.segments - 1).fill('unknown').concat([currentStatus]);
    }
    
    // If we have fewer segments than needed, pad with unknown
    if (segments.length < this.options.segments) {
      return Array(this.options.segments - segments.length).fill('unknown').concat(segments);
    }
    
    // If we have more segments than needed, take the most recent ones
    if (segments.length > this.options.segments) {
      return segments.slice(segments.length - this.options.segments);
    }
    
    // Otherwise, return as is
    return segments;
  }

  /**
   * Refresh uptime data for a domain
   * @param {HTMLElement} container - The container element
   * @param {string} domain - The domain name
   */
  refreshUptimeData(container, domain) {
    // Show loading state
    this.showLoadingState(container);
    
    // Fetch fresh data
    fetch(`/api/domains/${domain}/uptime/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (!data.success) {
        throw new Error(data.error || 'Unknown error');
      }
      
      // Update the chart with new data
      this.updateChart(container, data);
    })
    .catch(error => {
      console.error(`Error refreshing uptime data for ${domain}:`, error);
      this.showErrorState(container);
    });
  }

  /**
   * Show loading state for the chart
   * @param {HTMLElement} container - The container element
   */
  showLoadingState(container) {
    const segments = container.querySelectorAll('.uptime-bar');
    segments.forEach(segment => {
      segment.className = 'uptime-bar uptime-status-pending';
    });
  }

  /**
   * Show error state for the chart
   * @param {HTMLElement} container - The container element
   */
  showErrorState(container) {
    const chart = container.querySelector('.uptime-chart-new');
    if (chart) {
      chart.classList.add('uptime-error');
    }
    
    const percentageElement = container.querySelector('.uptime-percentage-new');
    if (percentageElement) {
      percentageElement.textContent = 'Error';
      percentageElement.className = 'uptime-percentage-new uptime-percentage-low';
    }
  }
}

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Create global instance
  window.uptimeChart = new UptimeChart({
    selector: '.uptime-visualization',
    segments: 12,
    timeUnit: 'hour',
    showPercentage: true
  });
});
