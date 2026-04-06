var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { ipcMain } from 'electron';
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);
// Get local subnet from ifconfig
function getLocalSubnet() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { stdout } = yield execAsync('ifconfig | grep "inet " | grep -v 127.0.0.1');
            const match = stdout.match(/inet (\d+\.\d+\.\d+)\.\d+/);
            if (match)
                return `${match[1]}.0/24`;
        }
        catch (_a) { }
        return '192.168.1.0/24';
    });
}
// Ping a single host
function pingHost(ip) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield execAsync(`ping -c 1 -W 1 ${ip}`, { timeout: 2000 });
            return true;
        }
        catch (_a) {
            return false;
        }
    });
}
// Get ARP table
function getArpTable() {
    return __awaiter(this, void 0, void 0, function* () {
        const arpMap = new Map();
        try {
            const { stdout } = yield execAsync('arp -a');
            const lines = stdout.split('\n');
            for (const line of lines) {
                const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([a-f0-9:]+)/i);
                if (match && match[2] !== '(incomplete)' && match[2] !== 'ff:ff:ff:ff:ff:ff') {
                    arpMap.set(match[1], match[2].toUpperCase());
                }
            }
        }
        catch (_a) { }
        return arpMap;
    });
}
// Lookup vendor from MAC OUI
function getVendor(mac) {
    if (!mac || mac === 'Unknown')
        return 'Unknown';
    const oui = mac.replace(/:/g, '').substring(0, 6).toUpperCase();
    const vendors = {
        'A4C3F0': 'Netgear', 'C83A35': 'Netgear', '204E7F': 'Netgear',
        'DCA632': 'Raspberry Pi', 'B827EB': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
        '3C22FB': 'Apple', 'A8BE27': 'Apple', '000A27': 'Apple', 'F0189B': 'Apple',
        '78D2F8': 'Apple', '7CD1C3': 'Apple', 'F09FC2': 'Apple', '8C8590': 'Apple',
        'F01898': 'Samsung', '8C7712': 'Samsung', '784FF4': 'Samsung',
        '18B169': 'Nest Labs', 'B8273B': 'Nest Labs',
        '001A2B': 'Dell', '14FEB5': 'Dell', 'F8BC12': 'Dell',
        '88E9FE': 'TP-Link', 'ACDE48': 'TP-Link', '50C7BF': 'TP-Link',
        'AC84C6': 'Asus', '049226': 'Asus',
        '000C29': 'VMware', '000569': 'VMware',
        '3417EB': 'Amazon',
    };
    return vendors[oui] || 'Unknown';
}
// Scan ports on a host using nc (netcat) - no root required
function scanPorts(ip, ports) {
    return __awaiter(this, void 0, void 0, function* () {
        const openPorts = [];
        const checks = ports.map((port) => __awaiter(this, void 0, void 0, function* () {
            try {
                yield execAsync(`nc -z -w 1 ${ip} ${port}`, { timeout: 1500 });
                openPorts.push(port);
            }
            catch (_a) { }
        }));
        yield Promise.all(checks);
        return openPorts.sort((a, b) => a - b);
    });
}
// Determine risk and issues from open ports and device type
function analyzeHost(ip, mac, vendor, ports) {
    const vendorLower = vendor.toLowerCase();
    let type = 'desktop';
    if (vendorLower.includes('apple') && ports.length === 0)
        type = 'mobile';
    else if (vendorLower.includes('apple'))
        type = 'laptop';
    else if (vendorLower.includes('netgear') || vendorLower.includes('cisco') ||
        vendorLower.includes('tp-link') || vendorLower.includes('asus'))
        type = 'router';
    else if (vendorLower.includes('samsung') || vendorLower.includes('lg') ||
        vendorLower.includes('sony') || vendorLower.includes('roku') ||
        vendorLower.includes('nest'))
        type = 'iot';
    else if (vendorLower.includes('raspberry') || vendorLower.includes('arduino'))
        type = 'iot';
    const highRiskPorts = {
        3389: 'RDP (Remote Desktop) exposed — remote access risk',
        5900: 'VNC (remote desktop) open — remote access risk',
        23: 'Telnet enabled — unencrypted remote access',
        21: 'FTP enabled — unencrypted file transfer',
        445: 'SMB file sharing open — ransomware target',
        139: 'NetBIOS enabled — legacy protocol',
        4444: 'Suspicious port 4444 open — possible backdoor',
    };
    const mediumRiskPorts = {
        22: 'SSH port open',
        80: 'HTTP web interface exposed',
        8080: 'HTTP alternate port open',
        8443: 'HTTPS alternate port open',
        7676: 'Unencrypted media protocol open',
        2323: 'Alternate Telnet port open',
    };
    let risk = 'low';
    const issues = [];
    for (const port of ports) {
        if (highRiskPorts[port]) {
            risk = 'high';
            issues.push(highRiskPorts[port]);
        }
        else if (mediumRiskPorts[port]) {
            if (risk !== 'high')
                risk = 'medium';
            issues.push(mediumRiskPorts[port]);
        }
    }
    if (type === 'iot' && risk === 'low') {
        risk = 'medium';
        issues.push('IoT device on primary network — segmentation recommended');
    }
    if (issues.length === 0) {
        issues.push('No risky open ports detected — healthy');
    }
    let name = vendor || 'Unknown Device';
    if (vendorLower.includes('netgear') || vendorLower.includes('cisco'))
        name = 'Router / Gateway';
    else if (vendorLower.includes('apple') && type === 'mobile')
        name = 'Apple Mobile Device';
    else if (vendorLower.includes('apple') && type === 'laptop')
        name = 'Apple Mac';
    else if (vendorLower.includes('apple') && type === 'desktop')
        name = 'Apple Device';
    else if (vendorLower.includes('samsung'))
        name = 'Samsung Device';
    else if (vendorLower.includes('nest'))
        name = 'Nest Smart Device';
    else if (vendorLower.includes('raspberry'))
        name = 'Raspberry Pi';
    else if (vendorLower.includes('dell'))
        name = 'Dell Computer';
    else if (vendorLower.includes('tp-link'))
        name = 'TP-Link Device';
    else if (ip.endsWith('.1') || ip.endsWith('.254'))
        name = 'Router / Gateway';
    return { ip, mac, vendor, name, type, ports, risk, issues };
}
export function registerScanHandlers() {
    ipcMain.handle('bsc:start-scan', (event, subnet) => __awaiter(this, void 0, void 0, function* () {
        try {
            // Parse subnet to get base IP and range
            const parts = subnet.split('/');
            const baseIp = parts[0].split('.');
            const prefix = parseInt(parts[1]) || 24;
            // For /24 scan 254 hosts, for larger networks cap at 254 for performance
            const base = `${baseIp[0]}.${baseIp[1]}.${baseIp[2]}`;
            const hosts = [];
            // Step 1: Ping sweep to discover live hosts
            event.sender.send('bsc:scan-progress', { phase: 'ping', message: 'Pinging hosts...' });
            const pingPromises = [];
            const liveIps = [];
            for (let i = 1; i <= 254; i++) {
                const ip = `${base}.${i}`;
                pingPromises.push(pingHost(ip).then(alive => {
                    if (alive)
                        liveIps.push(ip);
                }));
            }
            // Run pings in batches of 30
            const batchSize = 30;
            for (let i = 0; i < pingPromises.length; i += batchSize) {
                yield Promise.all(pingPromises.slice(i, i + batchSize));
            }
            // Step 2: Get ARP table for MAC addresses
            event.sender.send('bsc:scan-progress', { phase: 'arp', found: liveIps.length });
            const arpTable = yield getArpTable();
            // Add any ARP entries not caught by ping
            for (const [ip, mac] of arpTable) {
                if (ip.startsWith(base) && !liveIps.includes(ip)) {
                    liveIps.push(ip);
                }
            }
            if (liveIps.length === 0)
                return [];
            // Step 3: Port scan each live host
            event.sender.send('bsc:scan-progress', { phase: 'ports', found: liveIps.length });
            const TOP_PORTS = [21, 22, 23, 25, 80, 139, 443, 445, 3389, 4444, 5900, 7676, 8080, 8443, 8888];
            for (const ip of liveIps.sort()) {
                const mac = arpTable.get(ip) || 'Unknown';
                const vendor = getVendor(mac);
                const openPorts = yield scanPorts(ip, TOP_PORTS);
                const host = analyzeHost(ip, mac, vendor, openPorts);
                hosts.push(host);
                event.sender.send('bsc:scan-progress', { phase: 'host-done', ip, risk: host.risk });
            }
            return hosts;
        }
        catch (err) {
            console.error('Scan error:', err);
            throw new Error(err.message || 'Scan failed');
        }
    }));
}
