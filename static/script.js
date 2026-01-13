async function scanNetwork() {
    try {
        const response = await fetch('/scan_network');
        const data = await response.json();
        const container = document.getElementById('ipListContainer');
        container.innerHTML = '';

        if (data.ips.length === 0) {
            container.innerHTML = '<span>No IPs found in PCAP.</span>';
        } else {
            data.ips.forEach(ip => {
                const tag = document.createElement('span');
                tag.className = 'ip-tag';
                tag.textContent = ip;
                tag.onclick = () => {
                    document.getElementById('ipInput').value = ip;
                    analyzeIP();
                };
                container.appendChild(tag);
            });
        }
        document.getElementById('ipListPanel').classList.remove('hidden');
    } catch (e) {
        alert("Failed to scan network.");
    }
}

async function analyzeIP() {
    const ip = document.getElementById('ipInput').value.trim();
    if (!ip) {
        alert("Please enter an IP address.");
        return;
    }

    // UI Updates
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || "An error occurred.");
            document.getElementById('loading').classList.add('hidden');
            return;
        }

        // --- Render Results ---

        // 1. Score & Gauge
        const score = data.score;
        const status = data.status;

        if (status === "Not Reachable") {
            document.getElementById('scoreValue').textContent = "N/A";
            document.getElementById('statusText').textContent = status;

            const color = '#8b949e'; // Gray
            document.getElementById('statusText').style.color = color;
            document.querySelector('.gauge-container').style.background = '#30363d'; // Empty gauge

            // 2. Details
            document.getElementById('resIp').textContent = data.ip;
            document.getElementById('resReason').innerText = data.reason; // Use innerText for newlines

            // 3. Features (Clear)
            document.getElementById('featPackets').textContent = "-";
            document.getElementById('featSize').textContent = "-";
            document.getElementById('featRate').textContent = "-";
            document.getElementById('featPorts').textContent = "-";
            document.getElementById('featTcp').textContent = "-";
            document.getElementById('featDuration').textContent = "-";

        } else {
            document.getElementById('scoreValue').textContent = score;
            document.getElementById('statusText').textContent = status;

            // Determine Color
            let color = '#238636'; // Normal
            if (score > 30) color = '#d29922'; // Suspicious
            if (score > 60) color = '#da3633'; // Threat

            document.getElementById('statusText').style.color = color;

            // Update Gauge Gradient
            const gauge = document.querySelector('.gauge-container');
            gauge.style.background = `conic-gradient(${color} ${score}%, #30363d ${score}% 100%)`;

            // 2. Details
            document.getElementById('resIp').textContent = data.ip;
            document.getElementById('resReason').textContent = data.reason;

            // 3. Features
            if (data.features) {
                document.getElementById('featPackets').textContent = data.features.total_packets;
                document.getElementById('featSize').textContent = Math.round(data.features.avg_pkt_size) + " bytes";
                document.getElementById('featRate').textContent = data.features.pkt_rate.toFixed(2) + " pkt/sec";
                document.getElementById('featPorts').textContent = data.features.unique_ports;
                document.getElementById('featTcp').textContent = (data.features.tcp_ratio * 100).toFixed(1) + "%";
                document.getElementById('featDuration').textContent = data.features.flow_duration.toFixed(2) + " sec";
            }
        }

        // Show Results
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('results').classList.remove('hidden');

    } catch (e) {
        console.error(e);
        alert("Failed to connect to the server.");
        document.getElementById('loading').classList.add('hidden');
    }
}
