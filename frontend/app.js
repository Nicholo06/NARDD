const API_URL = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws/alerts';

const deviceTableBody = document.getElementById('device-table-body');
const alertsContainer = document.getElementById('alerts-container');
const alertCountEl = document.getElementById('alert-count');
const refreshBtn = document.getElementById('refresh-btn');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');

let alertCount = 0;
let ws;

function connectWS() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        statusDot.classList.remove('bg-red-500');
        statusDot.classList.add('bg-green-500');
        statusText.textContent = 'Connected';
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        addAlert(data);
        fetchDevices(); // Refresh list on new event
    };

    ws.onclose = () => {
        statusDot.classList.remove('bg-green-500');
        statusDot.classList.add('bg-red-500');
        statusText.textContent = 'Disconnected (Retrying...)';
        setTimeout(connectWS, 3000);
    };
}

async function fetchDevices() {
    try {
        const response = await fetch(`${API_URL}/devices`);
        const devices = await response.json();
        renderDevices(devices);
    } catch (error) {
        console.error('Error fetching devices:', error);
    }
}

function renderDevices(devices) {
    deviceTableBody.innerHTML = '';
    devices.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));

    devices.forEach(device => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-700/30 transition';
        
        const lastSeen = new Date(device.last_seen).toLocaleTimeString();
        const statusClass = device.is_trusted ? 'text-green-400' : 'text-yellow-400';
        const statusIcon = device.is_trusted ? '✓ Trusted' : '⚠ Untrusted';

        tr.innerHTML = `
            <td class="px-6 py-4 font-mono text-xs text-gray-300">${device.mac_address}</td>
            <td class="px-6 py-4 text-gray-100">${device.ip_address}</td>
            <td class="px-6 py-4 ${statusClass} font-medium">${statusIcon}</td>
            <td class="px-6 py-4 text-gray-400 text-sm">${lastSeen}</td>
            <td class="px-6 py-4">
                <button onclick="toggleTrust('${device.mac_address}', ${!device.is_trusted})" class="text-indigo-400 hover:text-indigo-300 text-sm font-semibold">
                    ${device.is_trusted ? 'Revoke Trust' : 'Trust Device'}
                </button>
            </td>
        `;
        deviceTableBody.appendChild(tr);
    });
}

async function toggleTrust(mac, isTrusted) {
    try {
        await fetch(`${API_URL}/devices/${mac}/trust?is_trusted=${isTrusted}`, {
            method: 'PATCH'
        });
        fetchDevices();
    } catch (error) {
        console.error('Error updating trust status:', error);
    }
}

function addAlert(alert) {
    const div = document.createElement('div');
    const isCritical = alert.severity === 'CRITICAL';
    
    div.className = `p-3 rounded-lg border text-sm animate-pulse ${isCritical ? 'bg-red-900/50 border-red-700' : 'bg-indigo-900/30 border-indigo-800'}`;
    
    const time = new Date().toLocaleTimeString();
    
    div.innerHTML = `
        <div class="flex justify-between items-start mb-1">
            <span class="font-bold uppercase text-xs ${isCritical ? 'text-red-400' : 'text-indigo-400'}">${alert.type}</span>
            <span class="text-[10px] text-gray-500">${time}</span>
        </div>
        <p class="text-gray-200 leading-tight">${alert.message}</p>
    `;
    
    alertsContainer.prepend(div);
    alertCount++;
    alertCountEl.textContent = alertCount;

    if (isCritical) {
        // Notification sound could be added here
        console.warn('SECURITY ALERT:', alert.message);
    }
}

refreshBtn.onclick = fetchDevices;

// Initial load
fetchDevices();
connectWS();
