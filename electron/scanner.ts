import { ipcMain } from 'electron'
import { exec } from 'child_process'
import { promisify } from 'util'

const execAsync = promisify(exec)
const isWindows = process.platform === 'win32'

async function getLocalSubnet(): Promise<string> {
  try {
    if (isWindows) {
      const { stdout } = await execAsync('ipconfig')
      const blocks = stdout.split(/\r?\n\r?\n/)
      for (const block of blocks) {
        if (block.includes('Default Gateway') &&
            !block.match(/Default Gateway[.\s]+:\s*\r?\n/) &&
            !block.match(/Default Gateway[.\s]+:\s+fe80/)) {
          const match = block.match(/IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+)\.\d+/)
          if (match) return `${match[1]}.0/24`
        }
      }
    } else {
      const { stdout } = await execAsync('ifconfig | grep "inet " | grep -v 127.0.0.1')
      const match = stdout.match(/inet (\d+\.\d+\.\d+)\.\d+/)
      if (match) return `${match[1]}.0/24`
    }
  } catch {}
  return '192.168.1.0/24'
}

async function pingHost(ip: string): Promise<boolean> {
  try {
    const cmd = isWindows
      ? `ping -n 1 -w 1000 ${ip}`
      : `ping -c 1 -W 1 ${ip}`
    await execAsync(cmd, { timeout: 2000 })
    return true
  } catch {
    return false
  }
}

async function getArpTable(): Promise<Map<string, string>> {
  const arpMap = new Map<string, string>()
  try {
    const { stdout } = await execAsync('arp -a')
    const lines = stdout.split('\n')
    for (const line of lines) {
      if (isWindows) {
        const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9\-]{17})/i)
        if (match) {
          const mac = match[2].replace(/-/g, ':').toUpperCase()
          arpMap.set(match[1], mac)
        }
      } else {
        const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([a-f0-9:]+)/i)
        if (match && match[2] !== '(incomplete)' && match[2] !== 'ff:ff:ff:ff:ff:ff') {
          arpMap.set(match[1], match[2].toUpperCase())
        }
      }
    }
  } catch {}
  return arpMap
}

function getVendor(mac: string): string {
  if (!mac || mac === 'Unknown') return 'Unknown'
  const oui = mac.replace(/:/g, '').substring(0, 6).toUpperCase()
  const vendors: Record<string, string> = {
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
  }
  return vendors[oui] || 'Unknown'
}

async function scanPorts(ip: string, ports: number[]): Promise<number[]> {
  const openPorts: number[] = []
  const checks = ports.map(async (port) => {
    try {
      if (isWindows) {
        const { stdout } = await execAsync(
          `powershell -Command "Test-NetConnection -ComputerName ${ip} -Port ${port} -InformationLevel Quiet -WarningAction SilentlyContinue"`,
          { timeout: 3000 }
        )
        if (stdout.trim() === 'True') openPorts.push(port)
      } else {
        await execAsync(`nc -z -w 1 ${ip} ${port}`, { timeout: 1500 })
        openPorts.push(port)
      }
    } catch {}
  })
  await Promise.all(checks)
  return openPorts.sort((a, b) => a - b)
}

function analyzeHost(ip: string, mac: string, vendor: string, ports: number[]): any {
  const vendorLower = vendor.toLowerCase()

  let type = 'desktop'
  if (vendorLower.includes('apple') && ports.length === 0) type = 'mobile'
  else if (vendorLower.includes('apple')) type = 'laptop'
  else if (vendorLower.includes('netgear') || vendorLower.includes('cisco') ||
           vendorLower.includes('tp-link') || vendorLower.includes('asus')) type = 'router'
  else if (vendorLower.includes('samsung') || vendorLower.includes('lg') ||
           vendorLower.includes('sony') || vendorLower.includes('roku') ||
           vendorLower.includes('nest')) type = 'iot'
  else if (vendorLower.includes('raspberry') || vendorLower.includes('arduino')) type = 'iot'

  const highRiskPorts: Record<number, string> = {
    3389: 'RDP (Remote Desktop) exposed — remote access risk',
    5900: 'VNC (remote desktop) open — remote access risk',
    23:   'Telnet enabled — unencrypted remote access',
    21:   'FTP enabled — unencrypted file transfer',
    445:  'SMB file sharing open — ransomware target',
    139:  'NetBIOS enabled — legacy protocol',
    4444: 'Suspicious port 4444 open — possible backdoor',
  }

  const mediumRiskPorts: Record<number, string> = {
    22:   'SSH port open',
    80:   'HTTP web interface exposed',
    8080: 'HTTP alternate port open',
    8443: 'HTTPS alternate port open',
    7676: 'Unencrypted media protocol open',
    2323: 'Alternate Telnet port open',
  }

  let risk = 'low'
  const issues: string[] = []

  for (const port of ports) {
    if (highRiskPorts[port]) {
      risk = 'high'
      issues.push(highRiskPorts[port])
    } else if (mediumRiskPorts[port]) {
      if (risk !== 'high') risk = 'medium'
      issues.push(mediumRiskPorts[port])
    }
  }

  if (type === 'iot' && risk === 'low') {
    risk = 'medium'
    issues.push('IoT device on primary network — segmentation recommended')
  }

  if (issues.length === 0) issues.push('No risky open ports detected — healthy')

  let name = vendor || 'Unknown Device'
  if (vendorLower.includes('netgear') || vendorLower.includes('cisco')) name = 'Router / Gateway'
  else if (vendorLower.includes('apple') && type === 'mobile') name = 'Apple Mobile Device'
  else if (vendorLower.includes('apple') && type === 'laptop') name = 'Apple Mac'
  else if (vendorLower.includes('apple') && type === 'desktop') name = 'Apple Device'
  else if (vendorLower.includes('samsung')) name = 'Samsung Device'
  else if (vendorLower.includes('nest')) name = 'Nest Smart Device'
  else if (vendorLower.includes('raspberry')) name = 'Raspberry Pi'
  else if (vendorLower.includes('dell')) name = 'Dell Computer'
  else if (vendorLower.includes('tp-link')) name = 'TP-Link Device'
  else if (ip.endsWith('.1') || ip.endsWith('.254')) name = 'Router / Gateway'

  return { ip, mac, vendor, name, type, ports, risk, issues }
}

export function registerScanHandlers() {
  ipcMain.handle('bsc:start-scan', async (event, subnet: string) => {
    try {
      const parts = subnet.split('/')
      const baseIp = parts[0].split('.')
      const base = `${baseIp[0]}.${baseIp[1]}.${baseIp[2]}`
      const hosts: any[] = []

      event.sender.send('bsc:scan-progress', { phase: 'ping', message: 'Pinging hosts...' })

      const liveIps: string[] = []
      const pingPromises: Promise<void>[] = []

      for (let i = 1; i <= 254; i++) {
        const ip = `${base}.${i}`
        pingPromises.push(
          pingHost(ip).then(alive => {
            if (alive) liveIps.push(ip)
          })
        )
      }

      const batchSize = 30
      for (let i = 0; i < pingPromises.length; i += batchSize) {
        await Promise.all(pingPromises.slice(i, i + batchSize))
      }

      event.sender.send('bsc:scan-progress', { phase: 'arp', found: liveIps.length })
      const arpTable = await getArpTable()

      for (const [ip] of arpTable) {
        if (ip.startsWith(base) && !liveIps.includes(ip)) {
          liveIps.push(ip)
        }
      }

      if (liveIps.length === 0) return []

      event.sender.send('bsc:scan-progress', { phase: 'ports', found: liveIps.length })

      const TOP_PORTS = [21, 22, 23, 25, 80, 139, 443, 445, 3389, 4444, 5900, 7676, 8080, 8443, 8888]

      for (const ip of liveIps.sort()) {
        const mac = arpTable.get(ip) || 'Unknown'
        const vendor = getVendor(mac)
        const openPorts = await scanPorts(ip, TOP_PORTS)
        const host = analyzeHost(ip, mac, vendor, openPorts)
        hosts.push(host)
        event.sender.send('bsc:scan-progress', { phase: 'host-done', ip, risk: host.risk })
      }

      return hosts

    } catch (err: any) {
      console.error('Scan error:', err)
      throw new Error(err.message || 'Scan failed')
    }
  })
}

export async function detectSubnet(): Promise<string> {
  return await getLocalSubnet()
}
