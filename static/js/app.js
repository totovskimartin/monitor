// Certificate Monitor App JS

// API utility functions for async operations
const API = {
    /**
     * Fetch data from an API endpoint with proper error handling
     * @param {string} url - The API endpoint URL
     * @param {Object} options - Fetch options
     * @returns {Promise<Object>} - The parsed JSON response
     */
    async fetch(url, options = {}) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

            const response = await fetch(url, {
                ...options,
                signal: controller.signal,
                headers: {
                    'Content-Type': 'application/json',
                    ...(options.headers || {})
                }
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`API Error (${url}):`, error);
            throw error;
        }
    },

    /**
     * Perform a GET request
     * @param {string} url - The API endpoint URL
     * @returns {Promise<Object>} - The parsed JSON response
     */
    async get(url) {
        return this.fetch(url);
    },

    /**
     * Perform a POST request with JSON body
     * @param {string} url - The API endpoint URL
     * @param {Object} data - The data to send in the request body
     * @returns {Promise<Object>} - The parsed JSON response
     */
    async post(url, data) {
        return this.fetch(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    /**
     * Perform a DELETE request
     * @param {string} url - The API endpoint URL
     * @returns {Promise<Object>} - The parsed JSON response
     */
    async delete(url) {
        return this.fetch(url, {
            method: 'DELETE'
        });
    }
};

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

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips properly with show/hide behavior
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltipTriggerList.length > 0) {
        tooltipTriggerList.forEach(el => {
            new bootstrap.Tooltip(el, {
                trigger: 'hover focus',
                boundary: 'window',
                html: false,
                delay: {
                    show: 50,
                    hide: 50
                }
            });
        });
    }

    // Add global click handler to hide tooltips
    document.addEventListener('click', function(e) {
        // Don't hide tooltips when clicking on action buttons
        if (e.target.closest('.action-btn') || e.target.closest('[data-bs-toggle="tooltip"]')) {
            return;
        }

        // Hide all tooltips when clicking elsewhere on the page
        const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(tooltipEl => {
            const tooltip = bootstrap.Tooltip.getInstance(tooltipEl);
            if (tooltip) {
                tooltip.hide();
            }
        });
    });

    // Initialize UI components
    initializeSidebar();
    initializeThemeToggle();
    initializeAutoRefresh();
    initializeModals();
    fixModalBackdropIssues();

    // Copy to clipboard functionality
    window.copyToClipboard = async function(text) {
        try {
            await navigator.clipboard.writeText(text);
            const toast = new bootstrap.Toast(document.getElementById('copyToast'));
            toast.show();
        } catch (err) {
            console.error('Failed to copy: ', err);
        }
    };
});

// Sidebar functionality
function initializeSidebar() {
    const sidebar = document.querySelector('.modern-sidebar');
    if (!sidebar) return;

    // Mobile menu functionality
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    if (mobileMenuToggle) {
        // Create overlay for mobile
        const overlay = document.createElement('div');
        overlay.className = 'mobile-overlay';
        document.body.appendChild(overlay);

        mobileMenuToggle.addEventListener('click', function() {
            sidebar.classList.toggle('mobile-visible');
            overlay.classList.toggle('visible');
        });

        // Close sidebar when clicking on overlay
        overlay.addEventListener('click', function() {
            sidebar.classList.remove('mobile-visible');
            overlay.classList.remove('visible');
        });
    }

    // Handle section headers with collapse functionality
    document.querySelectorAll('.nav-section-header').forEach(header => {
        header.addEventListener('click', function() {
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            this.setAttribute('aria-expanded', !isExpanded);
        });
    });
}

// Theme toggle functionality
function initializeThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    if (!themeToggle) return;

    const themeIcon = themeToggle.querySelector('i');

    // Get current theme from HTML attribute (already set in base.html)
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');

    // Update icon based on current theme
    if (currentTheme === 'dark' && themeIcon) {
        themeIcon.className = 'bi bi-sun';
    } else if (currentTheme === 'light' && themeIcon) {
        themeIcon.className = 'bi bi-moon';
    }

    // Theme toggle click handler
    themeToggle.addEventListener('click', function() {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        // Apply theme immediately
        document.documentElement.setAttribute('data-bs-theme', newTheme);

        // Store in localStorage
        localStorage.setItem('theme', newTheme);
        console.log('Theme toggled to: ' + newTheme);

        // Update icon
        if (themeIcon) {
            if (newTheme === 'dark') {
                themeIcon.className = 'bi bi-sun';
            } else {
                themeIcon.className = 'bi bi-moon';
            }
        }
    });
}

// Theme preference is now handled entirely by localStorage

// Fix modal backdrop issues globally
function fixModalBackdropIssues() {
    // Get all modals on the page
    const modals = document.querySelectorAll('.modal');

    // Add event listeners to each modal
    modals.forEach(modal => {
        // Check if we've already added our listener
        if (!modal.dataset.backdropFixed) {
            // Add hidden.bs.modal event listener
            modal.addEventListener('hidden.bs.modal', function() {
                console.log('Modal hidden event triggered for', modal.id);

                // Force remove all modal backdrops
                const backdrops = document.querySelectorAll('.modal-backdrop');
                backdrops.forEach(backdrop => {
                    console.log('Removing backdrop');
                    backdrop.remove();
                });

                // Force remove modal-open class and inline styles from body
                document.body.classList.remove('modal-open');
                document.body.style.removeProperty('overflow');
                document.body.style.removeProperty('padding-right');

                // Mark this modal as fixed
                modal.dataset.backdropFixed = 'true';
            });

            // Also handle the case where the modal is closed by clicking outside
            modal.addEventListener('click', function(event) {
                // Check if the click was on the modal backdrop (outside the modal content)
                if (event.target === modal) {
                    console.log('Click outside modal detected');

                    // Force close the modal properly
                    const modalInstance = bootstrap.Modal.getInstance(modal);
                    if (modalInstance) {
                        modalInstance.hide();
                    }
                }
            });
        }
    });

    // Add a global click handler for close buttons
    document.addEventListener('click', function(event) {
        // Check if the clicked element is a modal close button
        if (event.target.matches('[data-bs-dismiss="modal"]') ||
            event.target.closest('[data-bs-dismiss="modal"]')) {

            console.log('Modal close button clicked');

            // Force remove all modal backdrops after a short delay
            setTimeout(() => {
                const backdrops = document.querySelectorAll('.modal-backdrop');
                backdrops.forEach(backdrop => {
                    console.log('Removing backdrop after close button click');
                    backdrop.remove();
                });

                // Force remove modal-open class and inline styles from body
                document.body.classList.remove('modal-open');
                document.body.style.removeProperty('overflow');
                document.body.style.removeProperty('padding-right');
            }, 300); // Short delay to allow Bootstrap's own handlers to run first
        }
    });
}

// Auto-refresh functionality
function initializeAutoRefresh() {
    const refreshIndicator = document.getElementById('refresh-indicator');
    const refreshTimeDisplay = document.getElementById('refresh-time-display');
    const autoRefreshBtn = document.getElementById('autoRefreshBtn');
    const autoRefreshDropdown = document.getElementById('autoRefreshDropdown');
    const refreshOptionBtns = document.querySelectorAll('.auto-refresh-option');

    if (!refreshOptionBtns.length || !refreshIndicator || !refreshTimeDisplay || !autoRefreshBtn || !autoRefreshDropdown) return;

    let refreshInterval;
    let countdownInterval;
    let dropdownVisible = false;

    // Format time helper function
    const formatTime = (secs) => {
        const minutes = Math.floor(secs / 60);
        const seconds = secs % 60;
        return `${minutes}:${seconds.toString().padStart(2, '0')}`;
    };

    // Toggle dropdown visibility
    const toggleDropdown = () => {
        dropdownVisible = !dropdownVisible;
        autoRefreshDropdown.classList.toggle('show', dropdownVisible);

        // Add click outside listener when dropdown is shown
        if (dropdownVisible) {
            setTimeout(() => {
                document.addEventListener('click', handleOutsideClick);
            }, 10);
        } else {
            document.removeEventListener('click', handleOutsideClick);
        }
    };

    // Handle clicks outside the dropdown
    const handleOutsideClick = (event) => {
        if (!autoRefreshBtn.contains(event.target) && !autoRefreshDropdown.contains(event.target)) {
            dropdownVisible = false;
            autoRefreshDropdown.classList.remove('show');
            document.removeEventListener('click', handleOutsideClick);
        }
    };

    // Update countdown display
    const updateCountdown = (seconds) => {
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }

        let remainingSeconds = seconds;
        refreshTimeDisplay.textContent = formatTime(remainingSeconds);

        countdownInterval = setInterval(() => {
            remainingSeconds--;
            refreshTimeDisplay.textContent = formatTime(remainingSeconds);

            if (remainingSeconds <= 0) {
                clearInterval(countdownInterval);
            }
        }, 1000);
    };

    // Stop auto-refresh
    const stopAutoRefresh = () => {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }

        refreshIndicator.classList.add('paused');
        localStorage.removeItem('autoRefresh');
        refreshTimeDisplay.textContent = 'Off';

        // Update active button state
        refreshOptionBtns.forEach(btn => {
            btn.classList.toggle('active', parseInt(btn.dataset.minutes, 10) === 0);
        });
    };

    // Start auto-refresh
    const startAutoRefresh = (minutes) => {
        stopAutoRefresh(); // Clear any existing interval

        const milliseconds = minutes * 60 * 1000;
        refreshInterval = setInterval(() => {
            window.location.reload();
        }, milliseconds);

        refreshIndicator.classList.remove('paused');
        localStorage.setItem('autoRefresh', minutes);

        // Update active button state
        refreshOptionBtns.forEach(btn => {
            btn.classList.toggle('active', parseInt(btn.dataset.minutes, 10) === minutes);
        });

        // Update countdown display
        updateCountdown(minutes * 60);
    };

    // Set up auto-refresh button click handler
    autoRefreshBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleDropdown();
    });

    // Set up refresh option buttons
    refreshOptionBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const minutes = parseInt(this.dataset.minutes, 10);
            minutes === 0 ? stopAutoRefresh() : startAutoRefresh(minutes);

            // Hide dropdown after selection
            dropdownVisible = false;
            autoRefreshDropdown.classList.remove('show');
            document.removeEventListener('click', handleOutsideClick);
        });
    });

    // Restore auto-refresh setting from localStorage
    const savedRefresh = localStorage.getItem('autoRefresh');
    if (savedRefresh) {
        startAutoRefresh(parseInt(savedRefresh, 10));
    } else {
        // Set "Off" button as active by default
        refreshOptionBtns.forEach(btn => {
            if (parseInt(btn.dataset.minutes, 10) === 0) {
                btn.classList.add('active');
            }
        });
    }
}

// Modal functionality
function initializeModals() {
    // Get all modals on the page
    const modals = document.querySelectorAll('.modal');

    // Initialize each modal with proper event handlers
    modals.forEach(modal => {
        // Add hidden.bs.modal event listener to ensure proper cleanup
        modal.addEventListener('hidden.bs.modal', function() {
            console.log('Modal hidden event from initializeModals for', modal.id);

            // Force remove all modal backdrops
            const backdrops = document.querySelectorAll('.modal-backdrop');
            backdrops.forEach(backdrop => backdrop.remove());

            // Force remove modal-open class and inline styles from body
            document.body.classList.remove('modal-open');
            document.body.style.removeProperty('overflow');
            document.body.style.removeProperty('padding-right');
        });
    });

    // Certificate details modal
    const certDetailsModal = document.getElementById('certDetailsModal');
    if (certDetailsModal) {
        certDetailsModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            if (!button) return;

            const domain = button.getAttribute('data-domain');
            const status = button.getAttribute('data-status');
            const daysRemaining = button.getAttribute('data-days');
            const expiryDate = button.getAttribute('data-expiry');

            const modalTitle = certDetailsModal.querySelector('.modal-title');
            if (modalTitle) modalTitle.textContent = domain;

            const statusElement = document.getElementById('cert-status');
            if (statusElement) {
                statusElement.textContent = status.charAt(0).toUpperCase() + status.slice(1);
                statusElement.className = 'status-' + status;
            }

            const daysElement = document.getElementById('cert-days');
            if (daysElement) daysElement.textContent = daysRemaining;

            const expiryElement = document.getElementById('cert-expiry');
            if (expiryElement) expiryElement.textContent = expiryDate;
        });
    }

    // Add Domain modal - special handling
    const addDomainModal = document.getElementById('addDomainModal');
    if (addDomainModal) {
        // Add event listener for the close button
        const closeButtons = addDomainModal.querySelectorAll('.btn-close, [data-bs-dismiss="modal"]');
        closeButtons.forEach(button => {
            button.addEventListener('click', function() {
                console.log('Add Domain modal close button clicked');

                // Force cleanup after a short delay
                setTimeout(() => {
                    // Force remove all modal backdrops
                    const backdrops = document.querySelectorAll('.modal-backdrop');
                    backdrops.forEach(backdrop => backdrop.remove());

                    // Force remove modal-open class and inline styles from body
                    document.body.classList.remove('modal-open');
                    document.body.style.removeProperty('overflow');
                    document.body.style.removeProperty('padding-right');
                }, 300);
            });
        });
    }
}
