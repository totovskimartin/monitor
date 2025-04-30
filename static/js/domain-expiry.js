document.addEventListener('DOMContentLoaded', function() {
    // Domain details modal
    const domainDetailsModal = document.getElementById('domainDetailsModal');
    if (domainDetailsModal) {
        domainDetailsModal.addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            const domain = button.getAttribute('data-domain');
            const status = button.getAttribute('data-status');
            const days = button.getAttribute('data-days');
            const expiry = button.getAttribute('data-expiry');
            const registrar = button.getAttribute('data-registrar');

            // Update modal content
            const modalTitle = domainDetailsModal.querySelector('.modal-title');
            const statusCell = document.getElementById('domain-status');
            const daysCell = document.getElementById('domain-days');
            const expiryCell = document.getElementById('domain-expiry');
            const registrarCell = document.getElementById('domain-registrar');

            modalTitle.textContent = `Domain Details: ${domain}`;

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

            // Set registrar (remove the update timestamp if present)
            let registrarText = registrar || 'Unknown';
            let registrarDisplay = registrarText.replace(/ \(Updated: .*\)/, '');
            registrarCell.textContent = registrarDisplay;

            // Set data source
            const sourceCell = document.getElementById('domain-source');
            let sourceHtml = '';

            // For all WHOIS data
            const updateMatch = registrarText.match(/\(Updated: (.*)\)/);
            if (updateMatch) {
                const updateTime = updateMatch[1];
                sourceHtml = `<span class="badge bg-info">WHOIS Data</span> <small class="text-muted ms-2">Last updated: ${updateTime}</small>`;
            } else {
                sourceHtml = '<span class="badge bg-info">WHOIS Data</span>';
            }

            sourceCell.innerHTML = sourceHtml;
        });
    }
});
