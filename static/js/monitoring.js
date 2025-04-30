/**
 * Monitoring pages shared JavaScript functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize search functionality
    initializeSearch();
    
    // Initialize refresh buttons
    initializeRefreshButtons();
    
    // Initialize tooltips
    initializeTooltips();
});

/**
 * Initialize search functionality for monitoring tables
 */
function initializeSearch() {
    const searchInputs = document.querySelectorAll('.search-box input');
    
    searchInputs.forEach(input => {
        input.addEventListener('keyup', debounce(function() {
            const searchTerm = this.value.toLowerCase().trim();
            const table = this.closest('.modern-card').querySelector('.modern-table');
            
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr');
            let visibleCount = 0;
            
            rows.forEach(row => {
                const domainCell = row.querySelector('td:first-child');
                if (!domainCell) return;
                
                const domainText = domainCell.textContent.toLowerCase();
                
                if (searchTerm === '' || domainText.includes(searchTerm)) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show or hide empty state message
            const emptyState = this.closest('.modern-card').querySelector('.text-center.py-5');
            if (emptyState) {
                if (visibleCount === 0 && rows.length > 0) {
                    // Create a temporary empty state for search results
                    let tempEmptyState = table.querySelector('.temp-empty-state');
                    if (!tempEmptyState) {
                        tempEmptyState = document.createElement('tr');
                        tempEmptyState.className = 'temp-empty-state';
                        tempEmptyState.innerHTML = `<td colspan="4" class="text-center py-4">No matching domains found for "${searchTerm}"</td>`;
                        table.querySelector('tbody').appendChild(tempEmptyState);
                    } else {
                        tempEmptyState.querySelector('td').textContent = `No matching domains found for "${searchTerm}"`;
                        tempEmptyState.style.display = '';
                    }
                } else {
                    // Hide temporary empty state if it exists
                    const tempEmptyState = table.querySelector('.temp-empty-state');
                    if (tempEmptyState) {
                        tempEmptyState.style.display = 'none';
                    }
                }
            }
        }, 300));
    });
}

/**
 * Initialize refresh buttons for domains/hosts
 */
function initializeRefreshButtons() {
    // Refresh buttons in tables
    const refreshButtons = document.querySelectorAll('[data-action="refresh"]');
    
    refreshButtons.forEach(button => {
        button.addEventListener('click', function() {
            const domain = this.getAttribute('data-domain') || this.getAttribute('data-host');
            if (!domain) return;
            
            // Show loading state
            this.disabled = true;
            this.innerHTML = '<i class="bi bi-arrow-repeat spin"></i>';
            
            // Determine the endpoint based on the page
            let endpoint;
            if (window.location.pathname.includes('ssl_certificates')) {
                endpoint = `/api/ssl/${encodeURIComponent(domain)}/refresh`;
            } else if (window.location.pathname.includes('domain_expiry')) {
                endpoint = `/api/expiry/${encodeURIComponent(domain)}/refresh`;
            } else if (window.location.pathname.includes('ping_monitoring')) {
                endpoint = `/api/ping/${encodeURIComponent(domain)}/refresh`;
            } else {
                // Default to dashboard refresh
                const domainId = this.getAttribute('data-domain-id');
                if (domainId) {
                    endpoint = `/api/domains/${domainId}/refresh`;
                } else {
                    console.error('Unable to determine refresh endpoint');
                    this.disabled = false;
                    this.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
                    return;
                }
            }
            
            // Call API to refresh
            fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Flash success indicator
                    const row = this.closest('tr');
                    const originalBackground = row.style.backgroundColor;
                    row.style.backgroundColor = 'rgba(var(--bs-success-rgb), 0.1)';
                    
                    // Reload the page to show updated data
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    alert(`Failed to refresh: ${data.error || 'Unknown error'}`);
                    this.disabled = false;
                    this.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert(`An error occurred while refreshing: ${error.message}`);
                this.disabled = false;
                this.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
            });
        });
    });
    
    // Refresh buttons in modals
    const modalRefreshButtons = document.querySelectorAll('#refresh-cert-btn, #refresh-domain-btn, #refresh-ping-btn');
    
    modalRefreshButtons.forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal');
            const domain = modal.querySelector('[data-domain]')?.getAttribute('data-domain') || 
                          modal.querySelector('[data-host]')?.getAttribute('data-host');
            
            if (!domain) return;
            
            // Show loading state
            this.disabled = true;
            this.innerHTML = '<i class="bi bi-arrow-repeat spin me-1"></i> Refreshing...';
            
            // Determine the endpoint based on the modal
            let endpoint;
            if (modal.id === 'certDetailsModal') {
                endpoint = `/api/ssl/${encodeURIComponent(domain)}/refresh`;
            } else if (modal.id === 'domainDetailsModal') {
                endpoint = `/api/expiry/${encodeURIComponent(domain)}/refresh`;
            } else if (modal.id === 'pingDetailsModal') {
                endpoint = `/api/ping/${encodeURIComponent(domain)}/refresh`;
            } else {
                console.error('Unable to determine refresh endpoint');
                this.disabled = false;
                this.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i> Refresh Now';
                return;
            }
            
            // Call API to refresh
            fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Reload the page to show updated data
                    window.location.reload();
                } else {
                    alert(`Failed to refresh: ${data.error || 'Unknown error'}`);
                    this.disabled = false;
                    this.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i> Refresh Now';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert(`An error occurred while refreshing: ${error.message}`);
                this.disabled = false;
                this.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i> Refresh Now';
            });
        });
    });
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            delay: { show: 500, hide: 100 }
        });
    });
}

/**
 * Debounce function to limit how often a function can be called
 */
function debounce(func, wait = 300) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}
