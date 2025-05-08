// Alerts management for Certifly
document.addEventListener('DOMContentLoaded', function() {
    initializeAlerts();
});

/**
 * Initialize alert functionality
 * - Adds loading animation
 * - Auto-dismisses alerts after 5 seconds if not hovered
 */
function initializeAlerts() {
    const alerts = document.querySelectorAll('.modern-alert');

    alerts.forEach(alert => {
        // Add loading bar to each alert
        const loadingBar = document.createElement('div');
        loadingBar.className = 'alert-loading-bar';
        alert.appendChild(loadingBar);

        let dismissTimeout;
        let isHovered = false;

        // Set timeout to dismiss alert after 5 seconds if not hovered
        const startDismissTimeout = () => {
            dismissTimeout = setTimeout(() => {
                if (!isHovered) {
                    // If not hovered, add the hide class first for our custom animation
                    alert.classList.add('hide');

                    // Then dismiss the alert after the animation completes
                    setTimeout(() => {
                        const bsAlert = new bootstrap.Alert(alert);
                        bsAlert.close();
                    }, 600); // Match the transition duration (0.6s)
                }
            }, 5000); // 5 seconds
        };

        // Start the initial timeout
        startDismissTimeout();

        // Add hover event listeners
        alert.addEventListener('mouseenter', () => {
            isHovered = true;
            // Clear the dismiss timeout
            clearTimeout(dismissTimeout);
        });

        alert.addEventListener('mouseleave', () => {
            isHovered = false;
            // Restart the dismiss timeout
            startDismissTimeout();
        });

        // Handle manual close button
        const closeButton = alert.querySelector('.modern-alert-close');
        if (closeButton) {
            closeButton.addEventListener('click', (e) => {
                // Prevent default button behavior
                e.preventDefault();

                // Clear any existing timeout
                clearTimeout(dismissTimeout);

                // Add the hide class for our custom animation
                alert.classList.add('hide');

                // Close the alert after the animation completes
                setTimeout(() => {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }, 600); // Match the transition duration (0.6s)
            });
        }
    });
}
