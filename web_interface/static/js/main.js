// Connect to WebSocket server
const socket = io('http://127.0.0.1:5000');

// Chart instances
let trafficChart = null;
let featuresChart = null;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    setupEventListeners();
    setupSocketHandlers();
    console.log('[Dashboard] Initialized');
});

// ============================================
// Chart Initialization
// ============================================
function initializeCharts() {
    // Traffic Chart (Line Chart)
    const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/sec',
                data: [],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Packets'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            },
            plugins: {
                legend: {
                    display: true
                }
            }
        }
    });

    // Features Chart (Bar Chart)
    const featuresCtx = document.getElementById('features-chart').getContext('2d');
    featuresChart = new Chart(featuresCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Feature Values',
                data: [],
                backgroundColor: [
                    'rgba(231, 76, 60, 0.7)',
                    'rgba(52, 152, 219, 0.7)',
                    'rgba(46, 204, 113, 0.7)',
                    'rgba(241, 196, 15, 0.7)',
                    'rgba(155, 89, 182, 0.7)',
                    'rgba(230, 126, 34, 0.7)',
                    'rgba(149, 165, 166, 0.7)',
                    'rgba(26, 188, 156, 0.7)',
                    'rgba(52, 73, 94, 0.7)',
                    'rgba(192, 57, 43, 0.7)',
                    'rgba(142, 68, 173, 0.7)'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: '% of Max (UNSW-NB15)'
                    },
                    ticks: {
                        callback: v => v + '%'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// ============================================
// Event Listeners
// ============================================
function setupEventListeners() {
    // Attacker Controls
    document.getElementById('threads').addEventListener('input', (e) => {
        document.getElementById('thread-count').textContent = e.target.value;
    });

    document.getElementById('start-attack').addEventListener('click', startAttack);
    document.getElementById('stop-attack').addEventListener('click', stopAttack);

    // Client Controls
    document.getElementById('client-rate').addEventListener('input', (e) => {
        document.getElementById('client-rate-value').textContent = e.target.value + ' req/s';
    });

    document.getElementById('start-client').addEventListener('click', startClient);
    document.getElementById('stop-client').addEventListener('click', stopClient);

    // Edge Device Simulation Toggle
    document.getElementById('edge-mode-toggle').addEventListener('change', (e) => {
        const enabled = e.target.checked;
        console.log(`[Edge] Toggling edge mode: ${enabled ? 'ON' : 'OFF'}`);
        socket.emit('toggle_edge_mode', { enabled: enabled });

        // Update UI immediately
        const badge = document.getElementById('edge-device-badge');
        const specLaptop = document.getElementById('spec-col-laptop');
        const specRpi = document.getElementById('spec-col-rpi');

        if (enabled) {
            badge.className = 'device-badge device-rpi';
            badge.textContent = '🍓 Simulating: Raspberry Pi 5 (ARM Cortex-A76)';
            specLaptop.className = '';
            specRpi.className = 'spec-active';
        } else {
            badge.className = 'device-badge device-laptop';
            badge.textContent = '💻 Running on: Laptop (x86_64)';
            specLaptop.className = 'spec-active';
            specRpi.className = '';
        }
    });
}

// ============================================
// Attack Functions
// ============================================
function startAttack() {
    const target = document.getElementById('target').value;
    const [ip, port] = target.split(':');
    const threads = parseInt(document.getElementById('threads').value);

    console.log(`[Attack] Starting: ${ip}:${port} with ${threads} threads`);

    socket.emit('start_attack', {
        target_ip: ip || '127.0.0.1',
        target_port: parseInt(port) || 80,
        threads: threads
    });

    document.getElementById('start-attack').disabled = true;
    document.getElementById('stop-attack').disabled = false;
    document.getElementById('attack-status').textContent = 'Starting...';
}

function stopAttack() {
    console.log('[Attack] Stopping');
    socket.emit('stop_attack');

    document.getElementById('start-attack').disabled = false;
    document.getElementById('stop-attack').disabled = true;
}

// ============================================
// Client Traffic Functions
// ============================================
function startClient() {
    const url = document.getElementById('client-url').value;
    const rate = parseInt(document.getElementById('client-rate').value);

    console.log(`[Client] Starting: ${url} at ${rate} req/s`);

    socket.emit('start_traffic', {
        target_url: url,
        rate: rate
    });

    document.getElementById('start-client').disabled = true;
    document.getElementById('stop-client').disabled = false;
    document.getElementById('client-status').textContent = 'Starting...';
}

function stopClient() {
    console.log('[Client] Stopping');
    socket.emit('stop_traffic');

    document.getElementById('start-client').disabled = false;
    document.getElementById('stop-client').disabled = true;
}

// ============================================
// Socket Event Handlers
// ============================================
function setupSocketHandlers() {
    // Connection events
    socket.on('connect', () => {
        console.log('[WebSocket] Connected');
    });

    socket.on('disconnect', () => {
        console.log('[WebSocket] Disconnected');
    });

    socket.on('connection_response', (data) => {
        console.log('[WebSocket] Connection response:', data);
    });

    // Attack stats
    socket.on('attack_stats', (data) => {
        updateAttackStats(data);
    });

    // Detection results
    socket.on('detection_result', (data) => {
        updateDetectionResults(data);
    });

    // Traffic stats
    socket.on('traffic_stats', (data) => {
        updateTrafficStats(data);
    });

    // Response handlers
    socket.on('attack_response', (data) => {
        console.log('[Attack] Response:', data);
    });

    socket.on('traffic_response', (data) => {
        console.log('[Client] Response:', data);
    });

    socket.on('edge_mode_response', (data) => {
        console.log('[Edge] Mode response:', data);
    });
}

// ============================================
// Update Functions
// ============================================
function updateAttackStats(data) {
    document.getElementById('packet-count').textContent = data.total.toLocaleString();
    document.getElementById('packet-rate').textContent = data.rate.toLocaleString() + ' pkt/s';
    document.getElementById('attack-elapsed').textContent = data.elapsed + 's';

    if (data.status === 'attacking') {
        document.getElementById('attack-status').textContent = 'Attacking';
        document.getElementById('attack-status').style.color = '#e74c3c';
    } else if (data.status === 'stopped') {
        document.getElementById('attack-status').textContent = 'Stopped';
        document.getElementById('attack-status').style.color = '#95a5a6';
    }
}

function updateDetectionResults(data) {
    // Update alert
    const alert = document.getElementById('detection-alert');
    const confidence = Math.round(data.dos_probability * 100);

    if (data.is_attack) {
        alert.className = 'alert alert-danger';
        alert.innerHTML = '<span class="status-icon">⚠️</span><span class="status-text">DoS ATTACK DETECTED</span>';
    } else {
        alert.className = 'alert alert-success';
        alert.innerHTML = '<span class="status-icon">✅</span><span class="status-text">Normal Traffic</span>';
    }

    // Update confidence bar
    const confidenceBar = document.getElementById('confidence-bar');
    confidenceBar.style.width = confidence + '%';
    document.getElementById('confidence-value').textContent = confidence + '%';

    // Update stats
    document.getElementById('packets-analyzed').textContent = data.packet_count.toLocaleString();

    // Update traffic chart
    const now = new Date().toLocaleTimeString();
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(data.packet_count);

    // Keep last 20 data points
    if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
    }

    trafficChart.update();

    // Update features chart
    if (data.features) {
        updateFeaturesChart(data.features);
        updateFeaturesList(data.features);
    }

    // Update edge device metrics
    if (data.edge_metrics) {
        updateEdgeMetrics(data.edge_metrics);
    }

    console.log(`[Detection] ${data.is_attack ? '🚨 DoS' : '✅ Normal'} - Confidence: ${confidence}%`);
}

// Max values from UNSW-NB15 training data (used to normalize 0-100%)
const FEATURE_MAX = {
    'ct_srv_src': 36,
    'ct_dst_ltm': 23,
    'ct_srv_dst': 14,
    'synack':     2.10,
    'ackdat':     1.52,
    'tcprtt':     2.52,
    'dmean':      1458,
    'dpkts':      1716,
    'rate':       1000000,
    'sload':      5344000000,
    'sbytes':     338718
};

function updateFeaturesChart(features) {
    const labels = Object.keys(features);
    // Normalize each feature to 0-100% of its known max
    const values = labels.map(key => {
        const max = FEATURE_MAX[key] || 1;
        return Math.min((features[key] / max) * 100, 100);
    });

    featuresChart.data.labels = labels;
    featuresChart.data.datasets[0].data = values;
    featuresChart.update();
}

function updateFeaturesList(features) {
    const container = document.getElementById('feature-values');
    container.innerHTML = '';

    for (const [key, value] of Object.entries(features)) {
        const max = FEATURE_MAX[key] || 1;
        const pct = Math.min((value / max) * 100, 100).toFixed(1);
        const item = document.createElement('div');
        item.className = 'feature-item';
        item.innerHTML = `
            <span class="feature-name">${key}:</span>
            <span class="feature-value">${formatFeatureValue(value)} <small style="color:#888">(${pct}%)</small></span>
        `;
        container.appendChild(item);
    }
}

function formatFeatureValue(value) {
    if (typeof value === 'number') {
        if (value > 1000) {
            return value.toLocaleString(undefined, {maximumFractionDigits: 0});
        }
        return value.toFixed(2);
    }
    return value;
}

function updateTrafficStats(data) {
    document.getElementById('request-count').textContent = data.total.toLocaleString();
    document.getElementById('request-rate').textContent = data.rate.toLocaleString() + ' req/s';

    if (data.status === 'running') {
        document.getElementById('client-status').textContent = 'Running';
        document.getElementById('client-status').style.color = '#3498db';
    } else if (data.status === 'stopped') {
        document.getElementById('client-status').textContent = 'Stopped';
        document.getElementById('client-status').style.color = '#95a5a6';
    }
}

// ============================================
// Edge Device Metrics
// ============================================
function updateEdgeMetrics(metrics) {
    // Model size
    document.getElementById('edge-model-size').textContent = metrics.model_size_kb + ' KB';

    // Current inference time
    const inferEl = document.getElementById('edge-inference-time');
    inferEl.textContent = metrics.inference_ms.toFixed(2) + ' ms';
    inferEl.style.color = metrics.inference_ms < 10 ? '#27ae60' : '#e74c3c';

    // Average inference time
    const avgEl = document.getElementById('edge-avg-inference');
    avgEl.textContent = metrics.avg_inference_ms.toFixed(2) + ' ms';
    avgEl.style.color = metrics.avg_inference_ms < 10 ? '#27ae60' : '#e74c3c';

    // Total predictions
    document.getElementById('edge-total-preds').textContent = metrics.total_predictions.toLocaleString();

    // Threads
    document.getElementById('edge-threads').textContent = metrics.threads_used + ' (single-threaded)';

    // Slowdown factor
    const slowEl = document.getElementById('edge-slowdown');
    slowEl.textContent = metrics.slowdown_factor + 'x';
    slowEl.style.color = metrics.slowdown_factor > 1 ? '#e67e22' : '#27ae60';

    // Update spec table live speeds
    document.getElementById('spec-speed-laptop').textContent = metrics.laptop_ms.toFixed(2) + ' ms';
    if (metrics.edge_mode) {
        document.getElementById('spec-speed-rpi').textContent = metrics.inference_ms.toFixed(2) + ' ms (simulated)';
    } else {
        document.getElementById('spec-speed-rpi').textContent = '~' + (metrics.laptop_ms * 5).toFixed(1) + ' ms (estimated)';
    }

    // Update verdict
    const verdict = document.getElementById('edge-verdict');
    const verdictDetail = document.getElementById('verdict-detail');
    const avgMs = metrics.avg_inference_ms;

    if (avgMs > 0 && avgMs < 50) {
        verdict.className = 'edge-verdict verdict-pass';
        verdictDetail.innerHTML = `Model inference at <strong>${avgMs.toFixed(1)}ms</strong> avg — ` +
            `well within real-time requirement (&lt;100ms). ` +
            `Model size <strong>${metrics.model_size_kb} KB</strong> fits in RPi5 memory. ` +
            `<strong>Edge deployment confirmed viable.</strong>`;
    } else if (avgMs >= 50 && avgMs < 100) {
        verdict.className = 'edge-verdict verdict-warn';
        verdictDetail.innerHTML = `Inference at <strong>${avgMs.toFixed(1)}ms</strong> — ` +
            `acceptable but approaching limit. Consider reducing trees from 300 to 100.`;
    } else if (avgMs >= 100) {
        verdict.className = 'edge-verdict verdict-fail';
        verdictDetail.innerHTML = `Inference at <strong>${avgMs.toFixed(1)}ms</strong> — ` +
            `too slow for real-time. Reduce n_estimators or max_depth.`;
    }
}

// ============================================
// Utility Functions
// ============================================
function formatNumber(num) {
    return num.toLocaleString();
}

console.log('[Dashboard] Script loaded successfully');
