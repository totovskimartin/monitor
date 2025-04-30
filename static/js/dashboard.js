// Debounce function to limit how often a function can be called
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
    };
}

// Throttle function to limit how often a function can be called
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

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

            // Check if this is an anchor tag with href (View Statistics)
            if (this.tagName === 'A' && this.hasAttribute('href')) {
                // Allow default navigation behavior for anchor tags
                return;
            }

            // Prevent default for buttons
            e.preventDefault();

            // Process buttons with action attribute
            const action = this.dataset.action;
            if (!action) return;

            const domainId = this.dataset.domainId;
            const domainName = this.closest('tr').querySelector('.domain-name-link').textContent;

            switch(action) {
                case 'view':
                    // Allow default navigation for view action
                    return;
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

        // Get the domain's current monitoring settings using our API utility
        const data = await API.get(`/api/domains/${domainId}`);

        if (data.success) {
            // Populate the edit modal with the domain's data
            document.getElementById('editDomainId').value = domainId;
            document.getElementById('editDomainName').value = domainName;
            document.getElementById('originalDomainName').value = domainName;

            // Set checkboxes based on current monitoring settings
            document.getElementById('editMonitorSSL').checked = data.data.monitors.includes('ssl');
            document.getElementById('editMonitorExpiry').checked = data.data.monitors.includes('expiry');
            document.getElementById('editMonitorPing').checked = data.data.monitors.includes('ping');

            // Show the modal
            const modal = document.getElementById('editDomainModal');
            if (modal && !modal._bsModal) {
                modal._bsModal = new bootstrap.Modal(modal);
            }
            if (modal && modal._bsModal) {
                modal._bsModal.show();
            }
        } else {
            alert(`Failed to get domain details: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert(`An error occurred while getting domain details: ${error.message}`);
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
                // Keep the indicator, replace the text
                const newHtml = `
                    <span class="status-indicator status-indicator-${data.ssl_status.status}"></span>
                    ${statusText}
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
}
