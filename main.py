const express = require('express');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');
const ps = require('ps-node');
const fs = require('fs');
const path = require('path');

// Fungsi untuk menghasilkan kunci enkripsi
function generateKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Fungsi untuk mengenkripsi log
function encryptLog(logMessage, key) {
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), Buffer.alloc(16, 0));
    let encryptedMessage = cipher.update(logMessage, 'utf8', 'hex');
    encryptedMessage += cipher.final('hex');
    return encryptedMessage;
}

// Fungsi untuk mencatat log dengan enkripsi
function logEvent(message, key) {
    const timestamp = new Date().toISOString();
    const encryptedMessage = encryptLog(`${timestamp} - ${message}`, key);
    fs.appendFileSync('defense_log.enc', encryptedMessage + '\n');
}

// Fungsi untuk memonitor koneksi jaringan yang mencurigakan
function monitorNetwork(key) {
    const suspiciousPorts = [22, 80, 443]; // Contoh: port yang harus diawasi
    const connections = execSync('netstat -an').toString();
    const lines = connections.split('\n');
    let ipPacketCount = {};

    lines.forEach((line) => {
        suspiciousPorts.forEach((port) => {
            if (line.includes(`:${port}`) && line.includes('ESTABLISHED')) {
                const parts = line.trim().split(/\s+/);
                const ipAddress = parts[2].split(':')[0];
                const alertMessage = `Suspicious connection detected on port ${port} - IP Address: ${ipAddress} - Status: ESTABLISHED`;
                console.log(`[ALERT] ${alertMessage}`);
                logEvent(alertMessage, key);

                // Hitung paket per IP
                ipPacketCount[ipAddress] = (ipPacketCount[ipAddress] || 0) + 1;
            }
        });
    });

    // Blokir IP yang melebihi 50 paket per detik
    for (let [ip, count] of Object.entries(ipPacketCount)) {
        if (count > 50) {
            blockIp(ip, key);
        }
    }
}

// Fungsi untuk memblokir IP
function blockIp(ip, key) {
    const platform = os.platform();
    let rule = '';

    if (platform === 'linux') {
        rule = `iptables -A INPUT -s ${ip} -j DROP`;
    } else if (platform === 'win32') {
        rule = `netsh advfirewall firewall add rule name="Block ${ip}" dir=in action=block remoteip=${ip}`;
    }

    try {
        execSync(rule);
        const alertMessage = `Blocked IP: ${ip} for exceeding packet limit`;
        console.log(`[ALERT] ${alertMessage}`);
        logEvent(alertMessage, key);
    } catch (error) {
        console.error(`[ERROR] Failed to block IP: ${ip}`);
        console.error(` - Error: ${error}`);
    }
}

// Fungsi untuk memblokir paket ICMP, IGMP, dan RAW
function blockUnwantedPackets() {
    const platform = os.platform();
    const rules = [];

    if (platform === 'linux') {
        rules.push("iptables -A INPUT -p icmp -j DROP");
        rules.push("iptables -A INPUT -p igmp -j DROP");
        rules.push("iptables -A INPUT -p raw -j DROP");
    } else if (platform === 'win32') {
        rules.push('netsh advfirewall firewall add rule name="Block ICMP" dir=in action=block protocol=ICMPv4');
        rules.push('netsh advfirewall firewall add rule name="Block IGMP" dir=in action=block protocol=2');
        rules.push('netsh advfirewall firewall add rule name="Block RAW" dir=in action=block protocol=255');
    }

    rules.forEach((rule) => {
        try {
            execSync(rule);
            console.log(`[INFO] Applied packet block rule: ${rule}`);
        } catch (error) {
            console.error(`[ERROR] Failed to apply packet block rule: ${rule}`);
            console.error(` - Error: ${error}`);
        }
    });
}

// Fungsi utama untuk mengelola pertahanan
function main() {
    console.log("Running Super Defense Script...");

    // Generate encryption key for logs
    const key = generateKey();

    const platform = os.platform();

    // Blokir paket yang tidak diinginkan
    console.log("[INFO] Blocking unwanted packets...");
    blockUnwantedPackets();

    // Lakukan monitoring jaringan secara berkala
    setInterval(() => {
        console.log("[INFO] Monitoring network connections...");
        monitorNetwork(key);
    }, 60000); // Monitor setiap 60 detik
}

// Inisialisasi Express
const app = express();

// Middleware untuk parsing JSON
app.use(express.json());

// Import userRoutes
const userRoutes = require('./userRoutes');

// Routes
app.use('/api/users', userRoutes);

// Start server
app.listen(3000, () => {
    console.log('Server running on port 3000');
    main();
});
