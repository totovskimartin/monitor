/**
 * Reports functionality
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize report form handlers
    initReportForm();

    // Initialize export buttons
    initExportButtons();

    // Check if we need to auto-generate a report based on URL parameters
    autoGenerateReportFromParams();
});

/**
 * Initialize the report form and its event handlers
 */
function initReportForm() {
    const reportForm = document.getElementById('report-form');
    const reportType = document.getElementById('report-type');
    const organizationSelect = document.getElementById('organization');
    const domainsSelect = document.getElementById('domains');

    if (!reportForm) return;

    // Handle report type change
    reportType.addEventListener('change', function() {
        updateFormFields();
    });

    // Handle organization change
    if (organizationSelect) {
        organizationSelect.addEventListener('change', function() {
            updateDomainsList();
        });
    }

    // Handle form submission
    reportForm.addEventListener('submit', function(e) {
        e.preventDefault();
        generateReport();
    });

    // Initialize form fields based on current report type
    updateFormFields();
}

/**
 * Update form fields based on selected report type
 */
function updateFormFields() {
    const reportType = document.getElementById('report-type').value;

    // Hide all filter sections first
    document.querySelectorAll('.filter-section').forEach(section => {
        section.classList.add('d-none');
    });

    // Show the appropriate filter section based on report type
    switch (reportType) {
        case 'ssl_status':
            document.getElementById('ssl-filters').classList.remove('d-none');
            break;
        case 'domain_expiry':
            document.getElementById('domain-filters').classList.remove('d-none');
            break;
        case 'ping_uptime':
            document.getElementById('ping-filters').classList.remove('d-none');
            break;
        case 'all_domains':
            // For all domains, we don't show any specific filters
            break;
    }
}

/**
 * Update domains list based on selected organization
 */
function updateDomainsList() {
    const organizationId = document.getElementById('organization').value;
    const domainsSelect = document.getElementById('domains');

    if (organizationId === 'all') {
        // Show all domains
        Array.from(domainsSelect.options).forEach(option => {
            option.style.display = '';
        });
        return;
    }

    // Fetch domains for the selected organization
    fetch(`/api/organizations/${organizationId}/domains`)
        .then(response => response.json())
        .then(data => {
            // Clear current options except "All Domains"
            while (domainsSelect.options.length > 1) {
                domainsSelect.remove(1);
            }

            // Add new options
            data.domains.forEach(domain => {
                const option = document.createElement('option');
                option.value = domain.id;
                option.textContent = domain.name;
                domainsSelect.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error fetching domains:', error);
        });
}

/**
 * Generate a report based on form data
 */
function generateReport() {
    // Show loading state
    document.getElementById('report-placeholder').innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-3 text-muted">Generating report...</p>';
    document.getElementById('report-placeholder').classList.remove('d-none');
    document.getElementById('report-data').classList.add('d-none');

    // Get form data
    const formData = new FormData(document.getElementById('report-form'));

    // Make AJAX request to generate report
    fetch('/generate_report', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        // Hide placeholder and show report data
        document.getElementById('report-placeholder').classList.add('d-none');
        document.getElementById('report-data').classList.remove('d-none');

        // Update report title
        document.getElementById('report-title').textContent = data.title || 'Report Results';

        // Update summary data
        document.getElementById('total-domains').textContent = data.summary.total || '-';
        document.getElementById('healthy-domains').textContent = data.summary.healthy || '-';
        document.getElementById('warning-domains').textContent = data.summary.warning || '-';
        document.getElementById('critical-domains').textContent = data.summary.critical || '-';

        // Render charts
        renderStatusChart(data.charts.status);
        renderTrendChart(data.charts.trend);

        // Populate data table
        populateTable('report-table', data.table);

        // Populate alerts table
        populateTable('alerts-table', data.alerts);
    })
    .catch(error => {
        console.error('Error generating report:', error);
        document.getElementById('report-placeholder').innerHTML = '<i class="bi bi-exclamation-triangle text-danger display-1"></i><p class="mt-3 text-danger">Error generating report. Please try again.</p>';
        document.getElementById('report-placeholder').classList.remove('d-none');
    });
}

/**
 * Render the status distribution chart
 */
function renderStatusChart(data) {
    const ctx = document.getElementById('status-chart').getContext('2d');

    // Destroy existing chart if it exists
    if (window.statusChart) {
        window.statusChart.destroy();
    }

    // Create new chart
    window.statusChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: [
                    '#28a745', // Valid/Healthy
                    '#ffc107', // Warning
                    '#dc3545', // Critical/Error
                    '#6c757d'  // Unknown
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                },
                title: {
                    display: true,
                    text: 'Status Distribution'
                }
            }
        }
    });
}

/**
 * Render the trend over time chart
 */
function renderTrendChart(data) {
    const ctx = document.getElementById('trend-chart').getContext('2d');

    // Destroy existing chart if it exists
    if (window.trendChart) {
        window.trendChart.destroy();
    }

    // Create new chart
    window.trendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: data.datasets
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Trend Over Time'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Populate a table with data
 */
function populateTable(tableId, data) {
    const tableBody = document.getElementById(tableId).querySelector('tbody');
    tableBody.innerHTML = '';

    if (!data || data.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `<td colspan="5" class="text-center">No data available</td>`;
        tableBody.appendChild(row);
        return;
    }

    data.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = Object.values(item).map(value => `<td>${value}</td>`).join('');
        tableBody.appendChild(row);
    });
}

/**
 * Initialize export buttons
 */
function initExportButtons() {
    const exportCsv = document.getElementById('export-csv');
    const exportPdf = document.getElementById('export-pdf');
    const exportExcel = document.getElementById('export-excel');

    if (exportCsv) {
        exportCsv.addEventListener('click', function(e) {
            e.preventDefault();
            exportReport('csv');
        });
    }

    if (exportPdf) {
        exportPdf.addEventListener('click', function(e) {
            e.preventDefault();
            exportReport('pdf');
        });
    }

    if (exportExcel) {
        exportExcel.addEventListener('click', function(e) {
            e.preventDefault();
            exportReport('excel');
        });
    }
}

/**
 * Export report in the specified format
 */
function exportReport(format) {
    // Get form data
    const formData = new FormData(document.getElementById('report-form'));
    formData.append('export_format', format);

    // Create a form and submit it to trigger file download
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/export_report';

    for (const [key, value] of formData.entries()) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = value;
        form.appendChild(input);
    }

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
}

/**
 * Auto-generate a report based on URL parameters
 */
function autoGenerateReportFromParams() {
    // Get URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const reportType = urlParams.get('report_type');

    if (reportType) {
        // Set the report type in the form
        const reportTypeSelect = document.getElementById('report-type');
        if (reportTypeSelect) {
            reportTypeSelect.value = reportType;
            updateFormFields();
        }

        // Auto-generate the report
        setTimeout(generateReport, 500);
    }
}
