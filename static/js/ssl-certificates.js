document.addEventListener('DOMContentLoaded', function() {
    // Certificate details modal
    const certDetailsModal = document.getElementById('certDetailsModal');
    if (certDetailsModal) {
        let currentDomain = '';

        certDetailsModal.addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            const domain = button.getAttribute('data-domain');
            const status = button.getAttribute('data-status');
            const days = button.getAttribute('data-days');
            const expiry = button.getAttribute('data-expiry');

            // Store current domain for refresh button
            currentDomain = domain;

            // Update modal content
            const modalTitle = certDetailsModal.querySelector('.modal-title');
            const statusCell = document.getElementById('cert-status');
            const daysCell = document.getElementById('cert-days');
            const expiryCell = document.getElementById('cert-expiry');

            modalTitle.textContent = `Certificate Details: ${domain}`;

            // Set status with appropriate styling
            let statusHtml = '';
            if (status === 'valid') {
                statusHtml = '<span class="badge bg-success">Valid</span>';
            } else if (status === 'warning') {
                statusHtml = '<span class="badge bg-warning">Warning</span>';
            } else if (status === 'expired') {
                statusHtml = '<span class="badge bg-danger">Expired</span>';
            } else {
                statusHtml = '<span class="badge bg-secondary">Error</span>';
            }
            statusCell.innerHTML = statusHtml;

            // Set days remaining with appropriate styling
            let daysHtml = '';
            if (status === 'valid') {
                daysHtml = `<span class="text-success fw-bold">${days} days</span>`;
            } else if (status === 'warning') {
                daysHtml = `<span class="text-warning fw-bold">${days} days</span>`;
            } else if (status === 'expired') {
                daysHtml = `<span class="text-danger fw-bold">${days} days</span>`;
            } else {
                daysHtml = '<span class="text-secondary">Unknown</span>';
            }
            daysCell.innerHTML = daysHtml;

            // Set expiry date
            expiryCell.textContent = expiry || 'Unknown';
        });

        // Refresh button functionality
        const refreshCertBtn = document.getElementById('refresh-cert-btn');
        if (refreshCertBtn) {
            refreshCertBtn.addEventListener('click', function() {
                if (currentDomain) {
                    refreshCertificate(currentDomain);
                    // Close the modal
                    const modal = bootstrap.Modal.getInstance(certDetailsModal);
                    if (modal) {
                        modal.hide();
                    }
                }
            });
        }
    }
});

// Function to refresh certificate data
function refreshCertificate(domain) {
    // Show loading indicator
    const domainRow = document.querySelector(`.list-group-item:has(h5:contains('${domain}'))`);
    if (domainRow) {
        const statusIndicator = domainRow.querySelector('.status-indicator');
        if (statusIndicator) {
            statusIndicator.classList.add('refreshing');
        }
    }

    // Make AJAX request to refresh the certificate
    fetch(`/refresh_ssl_certificate/${domain}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Reload the page to show updated data
                window.location.reload();
            } else {
                alert('Error refreshing certificate: ' + data.message);
                // Remove loading indicator
                if (statusIndicator) {
                    statusIndicator.classList.remove('refreshing');
                }
            }
        })
        .catch(error => {
            console.error('Error refreshing certificate:', error);
            alert('Error refreshing certificate. Please try again.');
            // Remove loading indicator
            if (statusIndicator) {
                statusIndicator.classList.remove('refreshing');
            }
        });
}