const API_URL = `${window.location.protocol}//${window.location.host}`;
const WS_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/alerts`;

const deviceTableBody = document.getElementById('device-table-body');
const liveAlertsContainer = document.getElementById('live-alerts-container');
const historyAlertsContainer = document.getElementById('history-alerts-container');
const alertCountEl = document.getElementById('alert-count');
const refreshBtn = document.getElementById('refresh-btn');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const advancedBadge = document.getElementById('advanced-badge');
const liveTabBtn = document.getElementById('live-tab-btn');
const historyTabBtn = document.getElementById('history-tab-btn');

let alertCount = 0;
let ws;
let isAdvancedMode = false;
let blockedMacs = [];
let devices = []; // In-memory state

// Tab Logic
liveTabBtn.onclick = () => {
    liveAlertsContainer.classList.remove('hidden');
    historyAlertsContainer.classList.add('hidden');
    liveTabBtn.className = "text-sm font-bold text-indigo-400 border-b-2 border-indigo-400 pb-1";
    historyTabBtn.className = "text-sm font-bold text-gray-400 hover:text-gray-200 pb-1";
};

historyTabBtn.onclick = () => {
    liveAlertsContainer.classList.add('hidden');
    historyAlertsContainer.classList.remove('hidden');
    historyTabBtn.className = "text-sm font-bold text-indigo-400 border-b-2 border-indigo-400 pb-1";
    liveTabBtn.className = "text-sm font-bold text-gray-400 hover:text-gray-200 pb-1";
    fetchAlertHistory();
};

async function checkConfig() {
    try {
        const response = await fetch(`${API_URL}/config`);
        const config = await response.json();
        if (config.is_linux) {
            isAdvancedMode = true;
            advancedBadge.classList.remove('hidden');
        }
    } catch (e) { console.error(e); }
}

async function fetchBlocked() {
    try {
        const response = await fetch(`${API_URL}/blocked`);
        blockedMacs = await response.json();
    } catch (e) { console.error(e); }
}

async function fetchAlertHistory() {
    try {
        const response = await fetch(`${API_URL}/alerts`);
        const alerts = await response.json();
        historyAlertsContainer.innerHTML = '';
        alerts.forEach(alert => {
            historyAlertsContainer.appendChild(createAlertElement(alert, false));
        });
    } catch (e) { console.error(e); }
}

function connectWS() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        statusDot.className = "relative inline-flex rounded-full h-3 w-3 bg-green-500";
        statusText.textContent = 'Connected';
    };
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        addAlert(data);
        // Fast UI Update: Don't refetch everything, just update the single device
        if (data.mac) updateDeviceInMemory(data.mac, data.ip);
        else fetchDevices(); // Fallback
    };
    ws.onclose = () => {
        statusDot.className = "relative inline-flex rounded-full h-3 w-3 bg-red-500";
        statusText.textContent = 'Disconnected (Retrying...)';
        setTimeout(connectWS, 3000);
    };
}

async function fetchDevices() {
    try {
        await fetchBlocked();
        const response = await fetch(`${API_URL}/devices`);
        devices = await response.json();
        renderDevices();
    } catch (error) { console.error(error); }
}

function updateDeviceInMemory(mac, ip) {
    const dev = devices.find(d => d.mac_address === mac);
    if (dev) {
        dev.ip_address = ip;
        dev.last_seen = new Date().toISOString();
    } else {
        fetchDevices(); // If it's a totally new device, we need the full object
        return;
    }
    renderDevices();
}

function renderDevices() {
    deviceTableBody.innerHTML = '';
    devices.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));

    devices.forEach(device => {
        const tr = document.createElement('tr');
        const isBlocked = blockedMacs.includes(device.mac_address);
        tr.className = `transition ${isBlocked ? 'bg-red-900/20' : 'hover:bg-gray-700/30'}`;
        
        const lastSeen = new Date(device.last_seen).toLocaleTimeString();
        const statusClass = device.is_trusted ? 'text-green-400' : 'text-yellow-400';
        const statusIcon = device.is_trusted ? '✓ Trusted' : '⚠ Untrusted';

        let actionHtml = `
            <button onclick="toggleTrust('${device.mac_address}', ${!device.is_trusted})" class="text-indigo-400 hover:text-indigo-300 text-sm font-semibold mr-4">
                ${device.is_trusted ? 'Revoke Trust' : 'Trust'}
            </button>
        `;

        if (isAdvancedMode) {
            actionHtml += `
                <button onclick="toggleBlock('${device.mac_address}', ${!isBlocked})" class="${isBlocked ? 'text-red-400' : 'text-gray-400 hover:text-red-400'} text-sm font-semibold">
                    ${isBlocked ? 'UNBLOCK' : 'BLOCK'}
                </button>
            `;
        }

        tr.innerHTML = `
            <td class="px-6 py-4 font-mono text-xs text-gray-300">
                ${device.mac_address}
                ${isBlocked ? '<span class="ml-2 bg-red-600 text-[8px] px-1 rounded text-white font-bold">BLOCKED</span>' : ''}
            </td>
            <td class="px-6 py-4 text-gray-100">${device.ip_address}</td>
            <td class="px-6 py-4 ${statusClass} font-medium">${statusIcon}</td>
            <td class="px-6 py-4 text-gray-400 text-sm">${lastSeen}</td>
            <td class="px-6 py-4">${actionHtml}</td>
        `;
        deviceTableBody.appendChild(tr);
    });
}

function createAlertElement(alert, animate = true) {
    const div = document.createElement('div');
    const isCritical = alert.severity === 'CRITICAL';
    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    
    div.className = `p-3 rounded-lg border text-sm ${animate ? 'animate-pulse' : ''} ${isCritical ? 'bg-red-900/40 border-red-700' : 'bg-indigo-900/20 border-indigo-800'}`;
    div.innerHTML = `
        <div class="flex justify-between items-start mb-1">
            <span class="font-bold uppercase text-[10px] ${isCritical ? 'text-red-400' : 'text-indigo-400'}">${alert.type}</span>
            <span class="text-[9px] text-gray-500">${time}</span>
        </div>
        <p class="text-gray-300 leading-tight text-xs">${alert.message}</p>
    `;
    return div;
}

function addAlert(alert) {
    liveAlertsContainer.prepend(createAlertElement(alert, true));
    alertCount++;
    alertCountEl.textContent = alertCount;
}

async function toggleTrust(mac, isTrusted) {
    await fetch(`${API_URL}/devices/${mac}/trust?is_trusted=${isTrusted}`, { method: 'PATCH' });
    fetchDevices();
}

async function toggleBlock(mac, shouldBlock) {
    const endpoint = shouldBlock ? 'block' : 'unblock';
    await fetch(`${API_URL}/devices/${mac}/${endpoint}`, { method: 'POST' });
    fetchDevices();
}

refreshBtn.onclick = fetchDevices;

async function init() {
    await checkConfig();
    fetchDevices();
    connectWS();
}
init();
