/**
 * Timezone Selector
 * A modern search-based timezone selector with autocomplete
 */
document.addEventListener('DOMContentLoaded', function() {
    // Timezone data - city name and UTC offset
    const timezones = [
        // UTC-12:00 to UTC-10:00
        { value: 'Pacific/Midway', name: 'Midway Island', offset: '-11:00' },
        { value: 'Pacific/Niue', name: 'Niue', offset: '-11:00' },
        { value: 'Pacific/Pago_Pago', name: 'Pago Pago', offset: '-11:00' },
        { value: 'Pacific/Honolulu', name: 'Honolulu', offset: '-10:00' },
        { value: 'Pacific/Rarotonga', name: 'Rarotonga', offset: '-10:00' },
        { value: 'Pacific/Tahiti', name: 'Tahiti', offset: '-10:00' },

        // UTC-09:00 to UTC-08:00
        { value: 'America/Anchorage', name: 'Anchorage', offset: '-09:00' },
        { value: 'Pacific/Gambier', name: 'Gambier Islands', offset: '-09:00' },
        { value: 'America/Juneau', name: 'Juneau', offset: '-09:00' },
        { value: 'America/Los_Angeles', name: 'Los Angeles', offset: '-08:00' },
        { value: 'America/Tijuana', name: 'Tijuana', offset: '-08:00' },
        { value: 'America/Vancouver', name: 'Vancouver', offset: '-08:00' },
        { value: 'Pacific/Pitcairn', name: 'Pitcairn Islands', offset: '-08:00' },

        // UTC-07:00 to UTC-06:00
        { value: 'America/Phoenix', name: 'Phoenix', offset: '-07:00' },
        { value: 'America/Denver', name: 'Denver', offset: '-07:00' },
        { value: 'America/Mazatlan', name: 'Mazatlan', offset: '-07:00' },
        { value: 'America/Edmonton', name: 'Edmonton', offset: '-07:00' },
        { value: 'America/Chicago', name: 'Chicago', offset: '-06:00' },
        { value: 'America/Mexico_City', name: 'Mexico City', offset: '-06:00' },
        { value: 'America/Winnipeg', name: 'Winnipeg', offset: '-06:00' },
        { value: 'America/Belize', name: 'Belize', offset: '-06:00' },
        { value: 'America/Costa_Rica', name: 'Costa Rica', offset: '-06:00' },
        { value: 'America/Guatemala', name: 'Guatemala', offset: '-06:00' },
        { value: 'America/El_Salvador', name: 'El Salvador', offset: '-06:00' },
        { value: 'America/Managua', name: 'Managua', offset: '-06:00' },
        { value: 'America/Regina', name: 'Regina', offset: '-06:00' },

        // UTC-05:00 to UTC-04:00
        { value: 'America/New_York', name: 'New York', offset: '-05:00' },
        { value: 'America/Toronto', name: 'Toronto', offset: '-05:00' },
        { value: 'America/Bogota', name: 'Bogota', offset: '-05:00' },
        { value: 'America/Lima', name: 'Lima', offset: '-05:00' },
        { value: 'America/Panama', name: 'Panama', offset: '-05:00' },
        { value: 'America/Kingston', name: 'Kingston', offset: '-05:00' },
        { value: 'America/Havana', name: 'Havana', offset: '-05:00' },
        { value: 'America/Port-au-Prince', name: 'Port-au-Prince', offset: '-05:00' },
        { value: 'America/Caracas', name: 'Caracas', offset: '-04:00' },
        { value: 'America/Santiago', name: 'Santiago', offset: '-04:00' },
        { value: 'America/La_Paz', name: 'La Paz', offset: '-04:00' },
        { value: 'America/Manaus', name: 'Manaus', offset: '-04:00' },
        { value: 'America/Halifax', name: 'Halifax', offset: '-04:00' },
        { value: 'America/Santo_Domingo', name: 'Santo Domingo', offset: '-04:00' },
        { value: 'America/Asuncion', name: 'Asuncion', offset: '-04:00' },
        { value: 'America/Guyana', name: 'Guyana', offset: '-04:00' },

        // UTC-03:00 to UTC-01:00
        { value: 'America/Sao_Paulo', name: 'São Paulo', offset: '-03:00' },
        { value: 'America/Buenos_Aires', name: 'Buenos Aires', offset: '-03:00' },
        { value: 'America/Montevideo', name: 'Montevideo', offset: '-03:00' },
        { value: 'America/St_Johns', name: 'St. John\'s', offset: '-03:30' },
        { value: 'America/Godthab', name: 'Nuuk', offset: '-03:00' },
        { value: 'America/Argentina/Buenos_Aires', name: 'Argentina', offset: '-03:00' },
        { value: 'America/Cayenne', name: 'Cayenne', offset: '-03:00' },
        { value: 'America/Fortaleza', name: 'Fortaleza', offset: '-03:00' },
        { value: 'America/Recife', name: 'Recife', offset: '-03:00' },
        { value: 'Atlantic/Azores', name: 'Azores', offset: '-01:00' },
        { value: 'Atlantic/Cape_Verde', name: 'Cape Verde', offset: '-01:00' },

        // UTC+00:00
        { value: 'UTC', name: 'UTC', offset: '+00:00' },
        { value: 'Atlantic/Reykjavik', name: 'Reykjavik', offset: '+00:00' },
        { value: 'Europe/London', name: 'London', offset: '+00:00' },
        { value: 'Europe/Dublin', name: 'Dublin', offset: '+00:00' },
        { value: 'Europe/Lisbon', name: 'Lisbon', offset: '+00:00' },
        { value: 'Africa/Casablanca', name: 'Casablanca', offset: '+00:00' },
        { value: 'Africa/Monrovia', name: 'Monrovia', offset: '+00:00' },
        { value: 'Africa/Accra', name: 'Accra', offset: '+00:00' },
        { value: 'Atlantic/Canary', name: 'Canary Islands', offset: '+00:00' },

        // UTC+01:00 to UTC+02:00
        { value: 'Europe/Berlin', name: 'Berlin', offset: '+01:00' },
        { value: 'Europe/Paris', name: 'Paris', offset: '+01:00' },
        { value: 'Europe/Rome', name: 'Rome', offset: '+01:00' },
        { value: 'Europe/Madrid', name: 'Madrid', offset: '+01:00' },
        { value: 'Europe/Amsterdam', name: 'Amsterdam', offset: '+01:00' },
        { value: 'Europe/Brussels', name: 'Brussels', offset: '+01:00' },
        { value: 'Europe/Stockholm', name: 'Stockholm', offset: '+01:00' },
        { value: 'Europe/Vienna', name: 'Vienna', offset: '+01:00' },
        { value: 'Europe/Warsaw', name: 'Warsaw', offset: '+01:00' },
        { value: 'Europe/Budapest', name: 'Budapest', offset: '+01:00' },
        { value: 'Europe/Copenhagen', name: 'Copenhagen', offset: '+01:00' },
        { value: 'Europe/Malta', name: 'Malta', offset: '+01:00' },
        { value: 'Europe/Oslo', name: 'Oslo', offset: '+01:00' },
        { value: 'Europe/Prague', name: 'Prague', offset: '+01:00' },
        { value: 'Europe/Zurich', name: 'Zurich', offset: '+01:00' },
        { value: 'Africa/Lagos', name: 'Lagos', offset: '+01:00' },
        { value: 'Africa/Tunis', name: 'Tunis', offset: '+01:00' },
        { value: 'Africa/Algiers', name: 'Algiers', offset: '+01:00' },
        { value: 'Europe/Athens', name: 'Athens', offset: '+02:00' },
        { value: 'Europe/Bucharest', name: 'Bucharest', offset: '+02:00' },
        { value: 'Europe/Helsinki', name: 'Helsinki', offset: '+02:00' },
        { value: 'Europe/Kiev', name: 'Kiev', offset: '+02:00' },
        { value: 'Europe/Sofia', name: 'Sofia', offset: '+02:00' },
        { value: 'Europe/Riga', name: 'Riga', offset: '+02:00' },
        { value: 'Europe/Tallinn', name: 'Tallinn', offset: '+02:00' },
        { value: 'Europe/Vilnius', name: 'Vilnius', offset: '+02:00' },
        { value: 'Africa/Cairo', name: 'Cairo', offset: '+02:00' },
        { value: 'Africa/Johannesburg', name: 'Johannesburg', offset: '+02:00' },
        { value: 'Africa/Khartoum', name: 'Khartoum', offset: '+02:00' },
        { value: 'Africa/Tripoli', name: 'Tripoli', offset: '+02:00' },
        { value: 'Asia/Jerusalem', name: 'Jerusalem', offset: '+02:00' },
        { value: 'Asia/Beirut', name: 'Beirut', offset: '+02:00' },
        { value: 'Asia/Amman', name: 'Amman', offset: '+02:00' },
        { value: 'Asia/Damascus', name: 'Damascus', offset: '+02:00' },

        // UTC+03:00 to UTC+04:00
        { value: 'Europe/Moscow', name: 'Moscow', offset: '+03:00' },
        { value: 'Europe/Istanbul', name: 'Istanbul', offset: '+03:00' },
        { value: 'Asia/Riyadh', name: 'Riyadh', offset: '+03:00' },
        { value: 'Africa/Nairobi', name: 'Nairobi', offset: '+03:00' },
        { value: 'Asia/Baghdad', name: 'Baghdad', offset: '+03:00' },
        { value: 'Asia/Kuwait', name: 'Kuwait', offset: '+03:00' },
        { value: 'Asia/Qatar', name: 'Qatar', offset: '+03:00' },
        { value: 'Asia/Aden', name: 'Aden', offset: '+03:00' },
        { value: 'Europe/Minsk', name: 'Minsk', offset: '+03:00' },
        { value: 'Africa/Addis_Ababa', name: 'Addis Ababa', offset: '+03:00' },
        { value: 'Africa/Dar_es_Salaam', name: 'Dar es Salaam', offset: '+03:00' },
        { value: 'Africa/Djibouti', name: 'Djibouti', offset: '+03:00' },
        { value: 'Africa/Kampala', name: 'Kampala', offset: '+03:00' },
        { value: 'Africa/Mogadishu', name: 'Mogadishu', offset: '+03:00' },
        { value: 'Asia/Tehran', name: 'Tehran', offset: '+03:30' },
        { value: 'Asia/Dubai', name: 'Dubai', offset: '+04:00' },
        { value: 'Asia/Baku', name: 'Baku', offset: '+04:00' },
        { value: 'Asia/Muscat', name: 'Muscat', offset: '+04:00' },
        { value: 'Asia/Tbilisi', name: 'Tbilisi', offset: '+04:00' },
        { value: 'Asia/Yerevan', name: 'Yerevan', offset: '+04:00' },
        { value: 'Europe/Samara', name: 'Samara', offset: '+04:00' },
        { value: 'Indian/Mauritius', name: 'Mauritius', offset: '+04:00' },
        { value: 'Indian/Reunion', name: 'Reunion', offset: '+04:00' },
        { value: 'Asia/Kabul', name: 'Kabul', offset: '+04:30' },

        // UTC+05:00 to UTC+06:00
        { value: 'Asia/Karachi', name: 'Karachi', offset: '+05:00' },
        { value: 'Asia/Tashkent', name: 'Tashkent', offset: '+05:00' },
        { value: 'Asia/Yekaterinburg', name: 'Yekaterinburg', offset: '+05:00' },
        { value: 'Asia/Dushanbe', name: 'Dushanbe', offset: '+05:00' },
        { value: 'Asia/Ashgabat', name: 'Ashgabat', offset: '+05:00' },
        { value: 'Asia/Kolkata', name: 'Mumbai/New Delhi', offset: '+05:30' },
        { value: 'Asia/Colombo', name: 'Colombo', offset: '+05:30' },
        { value: 'Asia/Kathmandu', name: 'Kathmandu', offset: '+05:45' },
        { value: 'Asia/Dhaka', name: 'Dhaka', offset: '+06:00' },
        { value: 'Asia/Almaty', name: 'Almaty', offset: '+06:00' },
        { value: 'Asia/Bishkek', name: 'Bishkek', offset: '+06:00' },
        { value: 'Asia/Omsk', name: 'Omsk', offset: '+06:00' },
        { value: 'Asia/Thimphu', name: 'Thimphu', offset: '+06:00' },
        { value: 'Indian/Chagos', name: 'Chagos', offset: '+06:00' },
        { value: 'Asia/Yangon', name: 'Yangon', offset: '+06:30' },
        { value: 'Indian/Cocos', name: 'Cocos Islands', offset: '+06:30' },

        // UTC+07:00 to UTC+08:00
        { value: 'Asia/Bangkok', name: 'Bangkok', offset: '+07:00' },
        { value: 'Asia/Jakarta', name: 'Jakarta', offset: '+07:00' },
        { value: 'Asia/Ho_Chi_Minh', name: 'Ho Chi Minh City', offset: '+07:00' },
        { value: 'Asia/Krasnoyarsk', name: 'Krasnoyarsk', offset: '+07:00' },
        { value: 'Asia/Novosibirsk', name: 'Novosibirsk', offset: '+07:00' },
        { value: 'Asia/Phnom_Penh', name: 'Phnom Penh', offset: '+07:00' },
        { value: 'Asia/Vientiane', name: 'Vientiane', offset: '+07:00' },
        { value: 'Indian/Christmas', name: 'Christmas Island', offset: '+07:00' },
        { value: 'Asia/Shanghai', name: 'Shanghai', offset: '+08:00' },
        { value: 'Asia/Hong_Kong', name: 'Hong Kong', offset: '+08:00' },
        { value: 'Asia/Singapore', name: 'Singapore', offset: '+08:00' },
        { value: 'Asia/Taipei', name: 'Taipei', offset: '+08:00' },
        { value: 'Asia/Kuala_Lumpur', name: 'Kuala Lumpur', offset: '+08:00' },
        { value: 'Australia/Perth', name: 'Perth', offset: '+08:00' },
        { value: 'Asia/Irkutsk', name: 'Irkutsk', offset: '+08:00' },
        { value: 'Asia/Ulaanbaatar', name: 'Ulaanbaatar', offset: '+08:00' },
        { value: 'Asia/Manila', name: 'Manila', offset: '+08:00' },
        { value: 'Asia/Makassar', name: 'Makassar', offset: '+08:00' },
        { value: 'Asia/Brunei', name: 'Brunei', offset: '+08:00' },

        // UTC+09:00 to UTC+10:00
        { value: 'Asia/Tokyo', name: 'Tokyo', offset: '+09:00' },
        { value: 'Asia/Seoul', name: 'Seoul', offset: '+09:00' },
        { value: 'Asia/Yakutsk', name: 'Yakutsk', offset: '+09:00' },
        { value: 'Asia/Pyongyang', name: 'Pyongyang', offset: '+09:00' },
        { value: 'Asia/Dili', name: 'Dili', offset: '+09:00' },
        { value: 'Asia/Jayapura', name: 'Jayapura', offset: '+09:00' },
        { value: 'Pacific/Palau', name: 'Palau', offset: '+09:00' },
        { value: 'Australia/Darwin', name: 'Darwin', offset: '+09:30' },
        { value: 'Australia/Adelaide', name: 'Adelaide', offset: '+09:30' },
        { value: 'Australia/Brisbane', name: 'Brisbane', offset: '+10:00' },
        { value: 'Australia/Sydney', name: 'Sydney', offset: '+10:00' },
        { value: 'Australia/Melbourne', name: 'Melbourne', offset: '+10:00' },
        { value: 'Australia/Hobart', name: 'Hobart', offset: '+10:00' },
        { value: 'Asia/Vladivostok', name: 'Vladivostok', offset: '+10:00' },
        { value: 'Pacific/Guam', name: 'Guam', offset: '+10:00' },
        { value: 'Pacific/Port_Moresby', name: 'Port Moresby', offset: '+10:00' },
        { value: 'Pacific/Saipan', name: 'Saipan', offset: '+10:00' },
        { value: 'Pacific/Chuuk', name: 'Chuuk', offset: '+10:00' },

        // UTC+11:00 to UTC+14:00
        { value: 'Asia/Magadan', name: 'Magadan', offset: '+11:00' },
        { value: 'Pacific/Noumea', name: 'Noumea', offset: '+11:00' },
        { value: 'Pacific/Kosrae', name: 'Kosrae', offset: '+11:00' },
        { value: 'Pacific/Norfolk', name: 'Norfolk Island', offset: '+11:00' },
        { value: 'Pacific/Pohnpei', name: 'Pohnpei', offset: '+11:00' },
        { value: 'Pacific/Guadalcanal', name: 'Guadalcanal', offset: '+11:00' },
        { value: 'Pacific/Efate', name: 'Efate', offset: '+11:00' },
        { value: 'Asia/Kamchatka', name: 'Kamchatka', offset: '+12:00' },
        { value: 'Pacific/Auckland', name: 'Auckland', offset: '+12:00' },
        { value: 'Pacific/Fiji', name: 'Fiji', offset: '+12:00' },
        { value: 'Pacific/Funafuti', name: 'Funafuti', offset: '+12:00' },
        { value: 'Pacific/Majuro', name: 'Majuro', offset: '+12:00' },
        { value: 'Pacific/Tarawa', name: 'Tarawa', offset: '+12:00' },
        { value: 'Pacific/Wake', name: 'Wake Island', offset: '+12:00' },
        { value: 'Pacific/Wallis', name: 'Wallis', offset: '+12:00' },
        { value: 'Pacific/Nauru', name: 'Nauru', offset: '+12:00' },
        { value: 'Pacific/Chatham', name: 'Chatham Islands', offset: '+12:45' },
        { value: 'Pacific/Apia', name: 'Apia', offset: '+13:00' },
        { value: 'Pacific/Tongatapu', name: 'Nuku\'alofa', offset: '+13:00' },
        { value: 'Pacific/Enderbury', name: 'Enderbury', offset: '+13:00' },
        { value: 'Pacific/Fakaofo', name: 'Fakaofo', offset: '+13:00' },
        { value: 'Pacific/Kiritimati', name: 'Kiritimati', offset: '+14:00' }
    ];

    const searchInput = document.getElementById('timezone-search');
    const resultsContainer = document.getElementById('timezone-results');
    const selectedTimezoneInput = document.getElementById('timezone');
    const selectedTimezoneName = document.getElementById('selected-timezone-name');
    const currentTimePreview = document.getElementById('current-time-preview');
    const selectedTimezoneContainer = document.querySelector('.selected-timezone');

    if (!searchInput || !resultsContainer || !selectedTimezoneInput || !selectedTimezoneName || !currentTimePreview) {
        return; // Exit if any required element is missing
    }

    // Initialize with current timezone
    const currentTimezone = selectedTimezoneInput.value;
    const currentTimezoneData = timezones.find(tz => tz.value === currentTimezone) || { name: 'UTC', offset: '+00:00' };
    selectedTimezoneName.textContent = `${currentTimezoneData.name} (UTC ${currentTimezoneData.offset})`;
    updateCurrentTime(currentTimezone);

    // Set up interval to update the current time
    setInterval(() => {
        updateCurrentTime(selectedTimezoneInput.value);
    }, 1000);

    // Search input event handlers
    searchInput.addEventListener('focus', function() {
        showResults();
    });

    searchInput.addEventListener('input', function() {
        const query = this.value.toLowerCase().trim();
        filterResults(query);
        showResults();
    });

    // Close results when clicking outside
    document.addEventListener('click', function(event) {
        if (!searchInput.contains(event.target) && !resultsContainer.contains(event.target)) {
            hideResults();
        }
    });

    // Handle keyboard navigation
    searchInput.addEventListener('keydown', function(event) {
        const activeItem = resultsContainer.querySelector('.timezone-result-item.active');

        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault();
                if (activeItem) {
                    const nextItem = activeItem.nextElementSibling;
                    if (nextItem) {
                        activeItem.classList.remove('active');
                        nextItem.classList.add('active');
                        nextItem.scrollIntoView({ block: 'nearest' });
                    }
                } else {
                    const firstItem = resultsContainer.querySelector('.timezone-result-item');
                    if (firstItem) {
                        firstItem.classList.add('active');
                        firstItem.scrollIntoView({ block: 'nearest' });
                    }
                }
                break;
            case 'ArrowUp':
                event.preventDefault();
                if (activeItem) {
                    const prevItem = activeItem.previousElementSibling;
                    if (prevItem) {
                        activeItem.classList.remove('active');
                        prevItem.classList.add('active');
                        prevItem.scrollIntoView({ block: 'nearest' });
                    }
                } else {
                    const lastItem = resultsContainer.querySelector('.timezone-result-item:last-child');
                    if (lastItem) {
                        lastItem.classList.add('active');
                        lastItem.scrollIntoView({ block: 'nearest' });
                    }
                }
                break;
            case 'Enter':
                if (activeItem) {
                    event.preventDefault();
                    selectTimezone(activeItem.dataset.value);
                    hideResults();
                }
                break;
            case 'Escape':
                event.preventDefault();
                hideResults();
                break;
        }
    });

    // Filter and display matching timezones
    function filterResults(query) {
        resultsContainer.innerHTML = '';

        if (!query) {
            // Show all timezones if no query
            timezones.forEach(timezone => {
                addTimezoneToResults(timezone);
            });
            return;
        }

        // Filter timezones based on query
        const filteredTimezones = timezones.filter(timezone => {
            return timezone.name.toLowerCase().includes(query) ||
                   timezone.value.toLowerCase().includes(query) ||
                   `utc ${timezone.offset}`.toLowerCase().includes(query);
        });

        if (filteredTimezones.length === 0) {
            resultsContainer.innerHTML = '<div class="p-3 text-center text-muted">No matching timezones found</div>';
            return;
        }

        filteredTimezones.forEach(timezone => {
            addTimezoneToResults(timezone);
        });
    }

    // Add a timezone to the results container
    function addTimezoneToResults(timezone) {
        const item = document.createElement('div');
        item.className = 'timezone-result-item';
        item.dataset.value = timezone.value;

        item.innerHTML = `
            <span class="timezone-result-city">${timezone.name}</span>
            <span class="timezone-result-offset">UTC ${timezone.offset}</span>
        `;

        item.addEventListener('click', function() {
            selectTimezone(timezone.value);
            hideResults();
        });

        resultsContainer.appendChild(item);
    }

    // Select a timezone
    function selectTimezone(value) {
        const timezone = timezones.find(tz => tz.value === value);
        if (!timezone) return;

        selectedTimezoneInput.value = timezone.value;
        selectedTimezoneName.textContent = `${timezone.name} (UTC ${timezone.offset})`;
        searchInput.value = '';

        // Highlight the selected timezone briefly
        selectedTimezoneContainer.classList.add('highlight');
        setTimeout(() => {
            selectedTimezoneContainer.classList.remove('highlight');
        }, 1000);

        updateCurrentTime(timezone.value);
    }

    // Update the current time display
    function updateCurrentTime(timezone) {
        try {
            const now = new Date();
            let options = {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                timeZone: timezone
            };

            currentTimePreview.textContent = now.toLocaleTimeString([], options);
        } catch (error) {
            console.error('Error updating time:', error);
            currentTimePreview.textContent = new Date().toLocaleTimeString();
        }
    }

    // Show results container
    function showResults() {
        if (resultsContainer.children.length === 0) {
            filterResults('');
        }
        resultsContainer.classList.add('show');
    }

    // Hide results container
    function hideResults() {
        resultsContainer.classList.remove('show');
        const activeItem = resultsContainer.querySelector('.timezone-result-item.active');
        if (activeItem) {
            activeItem.classList.remove('active');
        }
    }

    // Initial population of results
    filterResults('');
});
