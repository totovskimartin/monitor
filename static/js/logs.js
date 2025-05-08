document.addEventListener('DOMContentLoaded', function() {
    // Initialize date pickers
    const startDateInput = document.getElementById('start_date');
    const endDateInput = document.getElementById('end_date');
    
    // Set default values for date inputs if not already set
    if (startDateInput && !startDateInput.value) {
        // Default to 7 days ago
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        startDateInput.value = formatDateForInput(sevenDaysAgo);
    }
    
    if (endDateInput && !endDateInput.value) {
        // Default to today
        const today = new Date();
        endDateInput.value = formatDateForInput(today);
    }
    
    // Refresh button functionality
    const refreshBtn = document.getElementById('refreshLogsBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            window.location.reload();
        });
    }
    
    // Helper function to format date for datetime-local input
    function formatDateForInput(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        
        return `${year}-${month}-${day}T${hours}:${minutes}`;
    }
});
