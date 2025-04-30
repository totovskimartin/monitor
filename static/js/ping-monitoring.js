document.addEventListener('DOMContentLoaded', function() {
    // Ping details modal
    const pingDetailsModal = document.getElementById('pingDetailsModal');
    if (pingDetailsModal) {
        pingDetailsModal.addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            const host = button.getAttribute('data-host');
            const status = button.getAttribute('data-status');
            const responseTime = button.getAttribute('data-response-time');
            const lastChecked = button.getAttribute('data-last-checked');
            
            // Update modal content
            const modalTitle = pingDetailsModal.querySelector('.modal-title');
            const statusCell = document.getElementById('ping-status');
            const responseTimeCell = document.getElementById('ping-response-time');
            const lastCheckedCell = document.getElementById('ping-last-checked');
            
            modalTitle.textContent = `Ping Details: ${host}`;
            
            // Set status with appropriate styling
            let statusHtml = '';
            if (status === 'up') {
                statusHtml = '<span class="badge bg-success">Online</span>';
            } else if (status === 'down') {
                statusHtml = '<span class="badge bg-danger">Offline</span>';
            } else {
                statusHtml = '<span class="badge bg-secondary">Unknown</span>';
            }
            statusCell.innerHTML = statusHtml;
            
            // Set response time
            if (status === 'up') {
                responseTimeCell.textContent = `${responseTime} ms`;
            } else {
                responseTimeCell.textContent = 'N/A';
            }
            
            // Set last checked time
            lastCheckedCell.textContent = lastChecked || 'Unknown';
            
            // Set up refresh button
            const refreshBtn = document.getElementById('refresh-ping-btn');
            refreshBtn.onclick = function() {
                refreshPingStatus(host, statusCell, responseTimeCell, lastCheckedCell);
            };
        });
    }
    
    // Initialize ping status refresh for all hosts
    initPingStatusRefresh();
});

// Function to refresh ping status for a specific host
function refreshPingStatus(host, statusCell, responseTimeCell, lastCheckedCell) {
    // Show loading indicators
    if (statusCell) statusCell.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Checking...';
    if (responseTimeCell) responseTimeCell.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
    
    fetch(`/check_ping/${host}`)
        .then(response => response.json())
        .then(data => {
            let statusHtml = '';
            if (data.ping_status === 'up') {
                statusHtml = '<span class="badge bg-success">Online</span>';
            } else if (data.ping_status === 'down') {
                statusHtml = '<span class="badge bg-danger">Offline</span>';
            } else {
                statusHtml = '<span class="badge bg-secondary">Unknown</span>';
            }
            
            if (statusCell) {
                statusCell.innerHTML = statusHtml;
            }
            
            if (responseTimeCell) {
                if (data.ping_status === 'up') {
                    responseTimeCell.textContent = `${data.response_time.toFixed(2)} ms`;
                } else {
                    responseTimeCell.textContent = 'N/A';
                }
            }
            
            if (lastCheckedCell) {
                const now = new Date();
                lastCheckedCell.textContent = now.toLocaleString();
            }
            
            // Update the ping indicator in the host list
            const indicators = document.querySelectorAll(`.ping-indicator[data-host="${host}"]`);
            indicators.forEach(indicator => {
                indicator.classList.remove('ping-up', 'ping-down', 'ping-unknown');
                indicator.classList.add(`ping-${data.ping_status}`);
                indicator.setAttribute('title', `Ping status: ${data.ping_status}`);
            });
        })
        .catch(error => {
            console.error('Error checking ping status:', error);
            if (statusCell) {
                statusCell.innerHTML = '<span class="badge bg-secondary">Error</span>';
            }
            if (responseTimeCell) {
                responseTimeCell.textContent = 'Error';
            }
        });
}

// Function to initialize ping status refresh for all hosts
function initPingStatusRefresh() {
    // Get all ping indicators
    const indicators = document.querySelectorAll('.ping-indicator');
    
    // Set up periodic refresh (every 60 seconds)
    setInterval(() => {
        indicators.forEach(indicator => {
            const host = indicator.getAttribute('data-host');
            if (host) {
                refreshPingStatus(host);
            }
        });
    }, 60000); // 60 seconds
}
