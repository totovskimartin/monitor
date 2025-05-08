// Using debounce and throttle functions from app.js

// Use requestAnimationFrame for smoother UI updates
function rafCallback(callback) {
    return function(...args) {
        window.requestAnimationFrame(() => callback.apply(this, args));
    };
}

document.addEventListener('DOMContentLoaded', function() {
    // Initialize progress bars - use requestAnimationFrame for better performance
    window.requestAnimationFrame(() => {
        document.querySelectorAll('.progress-bar[data-width]').forEach(bar => {
            bar.style.width = `${bar.dataset.width}%`;
        });
    });

    // Initialize action buttons
    initializeActionButtons();

    // Initialize search functionality
    initializeSearch();

    // Initialize uptime charts with new interactive features
    initializeUptimeCharts();

    // Auto-refresh is now initialized in app.js

    // Tooltips are now initialized in app.js

    // Initialize modals - only create instances when needed
    document.addEventListener('click', function(e) {
        // Check if the click is on a modal trigger
        const modalTrigger = e.target.closest('[data-bs-toggle="modal"]');
        if (modalTrigger) {
            const targetSelector = modalTrigger.getAttribute('data-bs-target');
            if (targetSelector) {
                const modal = document.querySelector(targetSelector);
                if (modal && !modal._bsModal) {
                    modal._bsModal = new bootstrap.Modal(modal);

                    // Add hidden event listener to ensure proper cleanup
                    modal.addEventListener('hidden.bs.modal', function() {
                        // Ensure backdrop is removed
                        const backdrop = document.querySelector('.modal-backdrop');
                        if (backdrop) {
                            backdrop.remove();
                        }
                        // Ensure body classes are cleaned up
                        document.body.classList.remove('modal-open');
                        document.body.style.removeProperty('overflow');
                        document.body.style.removeProperty('padding-right');
                    });
                }

                if (modal && modal._bsModal) {
                    modal._bsModal.show();
                }
            }
        }
    }, { passive: true });
});

function initializeActionButtons() {
    // Add Domain button
    const addDomainBtn = document.querySelector('[data-bs-target="#addDomainModal"]');
    if (addDomainBtn) {
        addDomainBtn.addEventListener('click', function(e) {
            e.preventDefault();
            const modal = new bootstrap.Modal(document.getElementById('addDomainModal'));
            modal.show();
        });
    }

    // Action buttons (view, edit, delete, refresh)
    document.querySelectorAll('.action-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            // Hide tooltip if it exists
            if (bootstrap && bootstrap.Tooltip) {
                const tooltip = bootstrap.Tooltip.getInstance(this);
                if (tooltip) {
                    tooltip.hide();
                }
            }

            // Process buttons with action attribute
            const action = this.dataset.action;
            if (!action) return;

            const domainId = this.dataset.domainId;
            const domainName = this.closest('tr').querySelector('.domain-name-link').textContent;

            // Check if this is an anchor tag with href (View Statistics)
            if (this.tagName === 'A' && this.hasAttribute('href') && action === 'view') {
                // Allow default navigation behavior for anchor tags
                return; // This allows the browser to follow the href
            }

            // Prevent default for buttons
            e.preventDefault();

            switch(action) {
                case 'view':
                    // If it's not an anchor tag, navigate programmatically
                    window.location.href = `/domain/${domainId}`;
                    break;
                case 'edit':
                    handleEdit(domainId, domainName);
                    break;
                case 'delete':
                    handleDelete(domainId, domainName);
                    break;
                case 'refresh':
                    handleRefresh(domainId, domainName);
                    break;
                // Add other action handlers as needed
            }
        });
    });
}

function initializeSearch() {
    const searchInput = document.querySelector('.search-box input');
    if (!searchInput) return;

    // Create a debounced search function for better performance
    const debouncedSearch = debounce(function(searchTerm) {
        // Use requestAnimationFrame for smoother UI updates
        window.requestAnimationFrame(() => {
            const tableRows = document.querySelectorAll('.modern-table tbody tr');
            let hasVisibleRows = false;

            tableRows.forEach(row => {
                // Skip the no-results message row if it exists
                if (row.id === 'no-search-results') return;

                const domainName = row.querySelector('.domain-name-link')?.textContent.toLowerCase() || '';
                const isVisible = searchTerm === '' || domainName.includes(searchTerm);

                // Only update the DOM if the visibility changes
                if ((row.style.display === 'none') !== !isVisible) {
                    row.style.display = isVisible ? '' : 'none';
                }

                if (isVisible) {
                    hasVisibleRows = true;
                }
            });

            // Handle the no results message
            let noResultsMessage = document.getElementById('no-search-results');

            if (!hasVisibleRows && searchTerm !== '') {
                if (!noResultsMessage) {
                    // Create a message if it doesn't exist
                    const tbody = document.querySelector('.modern-table tbody');
                    if (tbody) {
                        const messageRow = document.createElement('tr');
                        messageRow.id = 'no-search-results';
                        messageRow.innerHTML = `<td colspan="5" class="text-center py-4">No domains found matching "${searchTerm}"</td>`;
                        tbody.appendChild(messageRow);
                    }
                } else {
                    // Update existing message
                    const messageCell = noResultsMessage.querySelector('td');
                    if (messageCell) {
                        messageCell.textContent = `No domains found matching "${searchTerm}"`;
                    }
                    noResultsMessage.style.display = 'table-row';
                }
            } else if (noResultsMessage) {
                noResultsMessage.style.display = 'none';
            }
        });
    }, 150); // 150ms debounce time

    // Add input event listener with debounce
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase().trim();
        debouncedSearch(searchTerm);

        // Update clear button visibility immediately
        const clearButton = document.querySelector('.search-clear-btn');
        if (clearButton) {
            clearButton.style.display = this.value ? 'block' : 'none';
        }
    });

    // Add clear button functionality
    const searchBox = document.querySelector('.search-box');
    if (searchBox && !searchBox.querySelector('.search-clear-btn')) {
        const clearButton = document.createElement('button');
        clearButton.className = 'search-clear-btn';
        clearButton.innerHTML = '<i class="bi bi-x"></i>';
        clearButton.style.display = 'none';
        clearButton.setAttribute('type', 'button'); // Ensure it doesn't submit forms
        clearButton.setAttribute('aria-label', 'Clear search');
        searchBox.appendChild(clearButton);

        clearButton.addEventListener('click', function() {
            searchInput.value = '';
            // Trigger the input event
            searchInput.dispatchEvent(new Event('input'));
            // Focus back on the search input
            searchInput.focus();
        });
    }
}



async function handleEdit(domainId, domainName) {
    try {
        // Show loading state
        const editButton = document.querySelector(`[data-domain-id="${domainId}"][data-action="edit"]`);
        if (editButton) {
            // Hide tooltip if it exists
            const tooltip = bootstrap.Tooltip.getInstance(editButton);
            if (tooltip) {
                tooltip.hide();
            }

            editButton.disabled = true;
            editButton.innerHTML = '<i class="bi bi-hourglass-split"></i>';
        }

        try {
            // Get the domain's current monitoring settings using our API utility
            const data = await API.get(`/api/domains/${domainId}`);

            console.log("API response:", data); // Debug log

            // Populate the edit modal with the domain's data
            document.getElementById('editDomainId').value = domainId;
            document.getElementById('editDomainName').value = domainName;
            document.getElementById('originalDomainName').value = domainName;

            // Set checkboxes based on current monitoring settings
            if (data && data.domain) {
                document.getElementById('editMonitorSSL').checked = data.domain.ssl_monitored;
                document.getElementById('editMonitorExpiry').checked = data.domain.expiry_monitored;
                document.getElementById('editMonitorPing').checked = data.domain.ping_monitored;
            } else {
                // Fallback if API doesn't return expected format
                console.warn("API response format unexpected:", data);
                // Set default values based on what we can see in the UI
                const row = editButton.closest('tr');
                const hasSSL = row.querySelector('td:nth-child(2)').textContent.trim() !== 'Not monitored';
                const hasExpiry = row.querySelector('td:nth-child(3)').textContent.trim() !== 'Not monitored';
                const hasPing = row.querySelector('.ping-indicator') && !row.querySelector('.ping-indicator').classList.contains('ping-unknown');

                document.getElementById('editMonitorSSL').checked = hasSSL;
                document.getElementById('editMonitorExpiry').checked = hasExpiry;
                document.getElementById('editMonitorPing').checked = hasPing;
            }

            // Show the modal
            const modal = document.getElementById('editDomainModal');
            if (modal && !modal._bsModal) {
                modal._bsModal = new bootstrap.Modal(modal);
            }
            if (modal && modal._bsModal) {
                modal._bsModal.show();
            }
        } catch (apiError) {
            console.error('API Error:', apiError);

            // Fallback approach - just show the modal with the domain name
            document.getElementById('editDomainId').value = domainId;
            document.getElementById('editDomainName').value = domainName;
            document.getElementById('originalDomainName').value = domainName;

            // Show the modal
            const modal = document.getElementById('editDomainModal');
            if (modal && !modal._bsModal) {
                modal._bsModal = new bootstrap.Modal(modal);
            }
            if (modal && modal._bsModal) {
                modal._bsModal.show();
            }
        }
    } catch (error) {
        console.error('Error:', error);
        alert(`An error occurred while preparing the edit form: ${error.message}`);
    } finally {
        // Reset button state
        const editButton = document.querySelector(`[data-domain-id="${domainId}"][data-action="edit"]`);
        if (editButton) {
            editButton.disabled = false;
            editButton.innerHTML = '<i class="bi bi-pencil"></i>';
        }
    }
}

async function handleDelete(domainId, domainName) {
    // Get the delete button
    const button = document.querySelector(`[data-domain-id="${domainId}"][data-action="delete"]`);

    // Hide tooltip if it exists
    if (button && bootstrap && bootstrap.Tooltip) {
        const tooltip = bootstrap.Tooltip.getInstance(button);
        if (tooltip) {
            tooltip.hide();
        }
    }

    // Show the custom confirmation modal
    const deleteModal = document.getElementById('deleteConfirmModal');
    if (!deleteModal) return;

    // Set the domain name in the modal
    const domainNameElement = document.getElementById('deleteDomainName');
    if (domainNameElement) {
        domainNameElement.textContent = domainName;
    }

    // Initialize the modal if not already done
    if (!deleteModal._bsModal) {
        deleteModal._bsModal = new bootstrap.Modal(deleteModal);
    }

    // Show the modal
    deleteModal._bsModal.show();

    // Set up the confirm button
    const confirmBtn = document.getElementById('confirmDeleteBtn');
    if (confirmBtn) {
        // Remove any existing event listeners
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        // Add new event listener
        newConfirmBtn.addEventListener('click', async function() {
            // Hide the modal
            deleteModal._bsModal.hide();

            // Show loading state
            if (button) {
                button.disabled = true;
                button.innerHTML = '<i class="bi bi-hourglass-split"></i>';
            }

            try {
                // Call API to delete domain using our API utility
                const data = await API.delete(`/api/domains/${domainId}`);

                if (data.success) {
                    // Show success message with animation
                    const row = button.closest('tr');

                    // Use requestAnimationFrame for smoother animations
                    requestAnimationFrame(() => {
                        row.style.backgroundColor = 'rgba(var(--bs-danger-rgb), 0.1)';
                        row.style.transition = 'opacity 0.5s ease-out';

                        // Use a promise to handle the animation sequence
                        const animateRemoval = () => {
                            return new Promise(resolve => {
                                setTimeout(() => {
                                    row.style.opacity = '0';
                                    setTimeout(() => {
                                        row.remove();
                                        resolve();
                                    }, 500);
                                }, 300);
                            });
                        };

                        // Execute the animation and then check if table is empty
                        animateRemoval().then(() => {
                            // Check if table is empty
                            const tableRows = document.querySelectorAll('.modern-table tbody tr');
                            if (tableRows.length === 0) {
                                const tbody = document.querySelector('.modern-table tbody');
                                if (tbody) {
                                    const emptyRow = document.createElement('tr');
                                    emptyRow.innerHTML = '<td colspan="5" class="text-center py-4">No domains are being monitored. Add a domain to get started.</td>';
                                    tbody.appendChild(emptyRow);
                                }
                            }
                        });
                    });
                } else {
                    alert(`Failed to delete domain: ${data.error || 'Unknown error'}`);
                    if (button) {
                        button.disabled = false;
                        button.innerHTML = '<i class="bi bi-trash"></i>';
                    }
                }
            } catch (error) {
                console.error('Error:', error);
                alert(`An error occurred while deleting the domain: ${error.message}`);
                if (button) {
                    button.disabled = false;
                    button.innerHTML = '<i class="bi bi-trash"></i>';
                }
            }
        });
    }
}

async function handleRefresh(domainId, _) {
    // Show loading state
    const button = document.querySelector(`[data-domain-id="${domainId}"][data-action="refresh"]`);
    if (button) {
        // Hide tooltip if it exists
        const tooltip = bootstrap.Tooltip.getInstance(button);
        if (tooltip) {
            tooltip.hide();
        }

        button.disabled = true;
        button.innerHTML = '<i class="bi bi-arrow-repeat spin"></i>';
    }

    try {
        // Call API to refresh domain using our API utility
        const data = await API.post(`/api/domains/${domainId}/refresh`);

        if (data.success) {
            // Flash success indicator with animation
            const row = button.closest('tr');
            const originalBackground = row.style.backgroundColor;

            // Use requestAnimationFrame for smoother animations
            requestAnimationFrame(() => {
                row.style.backgroundColor = 'rgba(var(--bs-success-rgb), 0.1)';

                // Update the row with new data if available
                if (data.data) {
                    updateDomainRow(row, data.data);
                }

                // Reset background after animation
                setTimeout(() => {
                    row.style.backgroundColor = originalBackground;
                }, 1500);
            });
        } else {
            alert(`Failed to refresh domain: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert(`An error occurred while refreshing the domain: ${error.message}`);
    } finally {
        // Always reset button state
        if (button) {
            button.disabled = false;
            button.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
        }
    }
}

// Using the initializeAutoRefresh function from app.js

// Initialize uptime charts with interactive features
function initializeUptimeCharts() {
    // Add time labels to uptime charts
    document.querySelectorAll('.uptime-chart-modern').forEach(chart => {
        const domain = chart.dataset.domain;

        // Fix for newly added domains on page load
        // Check if this chart has multiple colored segments when it should only have one
        const segments = Array.from(chart.querySelectorAll('.uptime-segment-modern'));
        const coloredSegments = segments.filter(segment =>
            !segment.classList.contains('uptime-unknown-modern')
        );

        // If we have multiple colored segments, check if they're in an unusual pattern
        if (coloredSegments.length > 1) {
            const lastSegment = segments[segments.length - 1];
            const hasColoredMiddleSegments = segments.slice(0, -1).some(segment =>
                !segment.classList.contains('uptime-unknown-modern')
            );

            // If we have colored segments in the middle, it's likely a newly added domain
            if (hasColoredMiddleSegments && !lastSegment.classList.contains('uptime-unknown-modern')) {
                // Get the last segment's status
                const lastStatus = lastSegment.classList.contains('uptime-up-modern') ? 'up' :
                                  lastSegment.classList.contains('uptime-down-modern') ? 'down' : 'unknown';

                // Make all other segments unknown
                segments.forEach((segment, index) => {
                    if (index < segments.length - 1) {
                        segment.className = 'uptime-segment-modern uptime-unknown-modern';
                    }
                });

                console.log(`Fixed uptime segments for newly added domain ${domain} on page load`);
            }
        }

        // Add click event to open detailed view
        chart.addEventListener('click', () => {
            const domainRow = chart.closest('tr');
            if (domainRow) {
                const domainId = domainRow.dataset.domainId;
                if (domainId) {
                    window.location.href = `/domain/${domainId}`;
                }
            }
        });
    });

    // Initialize timeframe buttons
    document.querySelectorAll('.uptime-timeframe-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            // Prevent event bubbling to avoid triggering other click handlers
            e.stopPropagation();

            const domain = this.dataset.domain;
            const timeframe = this.dataset.timeframe;

            // Remove active class from all buttons in this group
            this.parentNode.querySelectorAll('.uptime-timeframe-btn').forEach(b => {
                b.classList.remove('active');
            });

            // Add active class to clicked button
            this.classList.add('active');

            // Show loading state
            const chart = document.querySelector(`.uptime-chart[data-domain="${domain}"]`);
            if (chart) {
                chart.style.opacity = '0.6';

                // Fetch new data based on timeframe
                fetch(`/api/domains/${domain}/uptime?timeframe=${timeframe}`)
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
        });
    });
}

// Update uptime chart with new data
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

    // Special case for newly added domains:
    // For newly added domains, we should only show the last segment as colored

    // Get the domain name from the chart's data attribute
    const domainName = chart.dataset.domain;

    // Check if this is a newly added domain by looking at the pattern of segments
    const nonUnknownCount = normalizedSegments.filter(s => s !== 'unknown').length;
    const hasColoredMiddleSegments = normalizedSegments.slice(0, -1).some(s => s !== 'unknown');

    // If we have colored segments in the middle but the domain was just added,
    // or if we have an unusual pattern of colored segments,
    // it's likely that this is a newly added domain with incorrect history
    if ((nonUnknownCount > 1 && hasColoredMiddleSegments) ||
        (normalizedSegments.indexOf('up') > -1 && normalizedSegments.indexOf('up') < normalizedSegments.length - 1)) {

        // Store the last segment status (current status)
        const lastStatus = normalizedSegments[normalizedSegments.length - 1];

        // If the last segment is colored, make all other segments unknown
        if (lastStatus !== 'unknown') {
            // Create a new array with all segments as unknown except the last one
            normalizedSegments = normalizedSegments.map((status, index) =>
                index === normalizedSegments.length - 1 ? lastStatus : 'unknown'
            );

            // Log for debugging
            console.log(`Fixed uptime segments for newly added domain ${domainName}`);
        }
    }

    // Create segments with modern design
    normalizedSegments.forEach((status, index) => {
        const segment = document.createElement('div');
        segment.className = `uptime-segment-modern uptime-${status}-modern`;
        segment.dataset.time = index;
        segment.dataset.status = status;

        // Add tooltip
        const tooltip = document.createElement('span');
        tooltip.className = 'uptime-tooltip-modern';
        tooltip.textContent = `${status.charAt(0).toUpperCase() + status.slice(1)} - ${12 - index} hour(s) ago`;
        segment.appendChild(tooltip);

        chart.appendChild(segment);
    });

    // Update percentage with modern design
    const container = chart.closest('.uptime-container');
    if (container) {
        // Find or create percentage element
        let percentageElement = container.querySelector('.uptime-percentage-modern');
        if (!percentageElement) {
            percentageElement = document.createElement('div');
            percentageElement.className = 'uptime-percentage-modern';
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

function updateDomainRow(row, data) {
    // Update SSL status if available
    if (data.ssl_status) {
        const sslCell = row.querySelector('td:nth-child(2)');
        if (sslCell) {
            const statusIndicator = sslCell.querySelector('.status-indicator');
            if (statusIndicator) {
                // Remove all status classes
                statusIndicator.classList.remove('status-indicator-valid', 'status-indicator-warning', 'status-indicator-expired', 'status-indicator-error');
                // Add the new status class
                statusIndicator.classList.add(`status-indicator-${data.ssl_status.status}`);
            }

            // Update the text
            const statusText = data.ssl_status.status === 'valid' ?
                `Valid (${data.ssl_status.days_remaining} days)` :
                data.ssl_status.status === 'warning' ?
                `Warning (${data.ssl_status.days_remaining} days)` :
                data.ssl_status.status === 'expired' ?
                'Expired' : 'Error';

            // Replace the text node
            const textContainer = sslCell.querySelector('div');
            if (textContainer) {
                // Keep the indicator, replace the text with proper formatting
                const newHtml = `
                    ${statusText}
                    <i class="bi bi-${data.ssl_status.status === 'valid' ? 'check-circle-fill text-success' :
                                     data.ssl_status.status === 'warning' ? 'exclamation-triangle-fill text-warning' :
                                     'x-circle-fill text-danger'} ms-2"></i>
                `;
                textContainer.innerHTML = newHtml;
            }
        }
    }

    // Update domain expiry status if available
    if (data.domain_status) {
        const expiryCell = row.querySelector('td:nth-child(3)');
        if (expiryCell) {
            const statusPill = expiryCell.querySelector('.status-pill');
            if (statusPill) {
                // Remove all status classes
                statusPill.classList.remove('status-pill-valid', 'status-pill-warning', 'status-pill-expired', 'status-pill-error', 'status-pill-unknown');
                // Add the new status class
                statusPill.classList.add(`status-pill-${data.domain_status.status}`);
                // Update the text
                statusPill.textContent = `${data.domain_status.days_remaining} days`;
            }
        }
    }

    // Update ping status if available
    if (data.ping_status) {
        const healthCell = row.querySelector('td:nth-child(4)');
        if (healthCell) {
            const pingIndicator = healthCell.querySelector('.ping-indicator');
            if (pingIndicator) {
                // Remove all status classes
                pingIndicator.classList.remove('ping-up', 'ping-down', 'ping-unknown');
                // Add the new status class
                pingIndicator.classList.add(`ping-${data.ping_status.status}`);
            }
        }
    }

    // Update uptime chart if available
    if (data.uptime_percentage !== undefined) {
        const uptimeCell = row.querySelector('td:nth-child(4)');
        if (uptimeCell) {
            const chart = uptimeCell.querySelector('.uptime-chart');
            if (chart) {
                // Always pass the segments, even if they're empty or undefined
                // The updateUptimeChart function will handle normalization
                updateUptimeChart(chart, data.uptime_segments || [], data.uptime_percentage || 0);
            }
        }
    }
}
