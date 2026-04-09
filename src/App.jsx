import { useState, useEffect, useRef } from "react";

const NAVY = "#1a1d35";
const NAVY2 = "#12142a";
const GOLD = "#c9a84c";
const TEAL = "#c9a84c";
const WHITE = "#f0f2ff";
const DIM = "#8892b0";

const FAKE_HOSTS = [
  { ip: "192.168.1.1",  mac: "A4:C3:F0:1B:2D:9E", vendor: "Netgear",      name: "Router / Gateway",     type: "router",  ports: [80,443,22],       risk: "medium", issues: ["Default admin credentials detected","HTTP admin interface exposed","SSH port open"] },
  { ip: "192.168.1.10", mac: "DC:A6:32:4F:88:12", vendor: "Raspberry Pi", name: "Raspberry Pi Device",  type: "iot",     ports: [22,8080,5900],    risk: "high",   issues: ["VNC (remote desktop) open on port 5900","Outdated SSH version","No firewall rules detected"] },
  { ip: "192.168.1.15", mac: "3C:22:FB:B0:C4:77", vendor: "Apple",        name: "MacBook Pro",          type: "laptop",  ports: [5353],            risk: "low",    issues: ["mDNS broadcasting device info"] },
  { ip: "192.168.1.20", mac: "F0:18:98:E2:11:AC", vendor: "Samsung",      name: "Smart TV",             type: "iot",     ports: [7676,8001,9197],  risk: "high",   issues: ["Unencrypted media protocol on port 7676","Remote management enabled","Firmware not updated in 18+ months"] },
  { ip: "192.168.1.25", mac: "B8:27:EB:6C:01:23", vendor: "Nest Labs",    name: "Nest Thermostat",      type: "iot",     ports: [9543],            risk: "medium", issues: ["IoT device on primary network","No network segmentation"] },
  { ip: "192.168.1.30", mac: "00:1A:2B:3C:4D:5E", vendor: "Dell",         name: "Windows Desktop",      type: "desktop", ports: [135,139,445,3389],risk: "high",   issues: ["RDP (Remote Desktop) exposed on port 3389","SMB file sharing open","NetBIOS enabled"] },
  { ip: "192.168.1.40", mac: "88:E9:FE:12:77:B0", vendor: "TP-Link",      name: "Wi-Fi Extender",       type: "router",  ports: [80,443],          risk: "medium", issues: ["Admin web interface accessible","Using WPA2 — WPA3 recommended"] },
  { ip: "192.168.1.55", mac: "AC:DE:48:00:11:22", vendor: "Apple",        name: "iPhone",               type: "mobile",  ports: [],                risk: "low",    issues: ["No open ports detected — healthy"] },
];

const RISK_COLOR = { low: "#2ecc71", medium: "#f39c12", high: "#e74c3c" };
const RISK_BG    = { low: "#0a2e1a", medium: "#2e1c00", high: "#2e0a0a" };
const TYPE_ICON  = { router: "⬡", iot: "◈", laptop: "▣", desktop: "▣", mobile: "▤" };

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function RiskBadge({ risk }) {
  return (
    <span style={{ background: RISK_BG[risk], color: RISK_COLOR[risk], border: `1px solid ${RISK_COLOR[risk]}`,
      borderRadius: 3, padding: "2px 8px", fontSize: 10, fontWeight: 700, letterSpacing: 1,
      textTransform: "uppercase", fontFamily: "'Courier New', monospace" }}>
      {risk}
    </span>
  );
}

function HostCard({ host, onClick, selected }) {
  return (
    <div onClick={() => onClick(host)}
      style={{ background: selected ? "#1e2245" : "#12142a", border: `1px solid ${selected ? TEAL : "#2a2d4a"}`,
        borderRadius: 6, padding: "12px 16px", cursor: "pointer", marginBottom: 8, transition: "all 0.15s",
        display: "flex", alignItems: "center", gap: 14 }}>
      <div style={{ width: 32, height: 32, borderRadius: "50%", background: "#1a1d35",
        border: `2px solid ${RISK_COLOR[host.risk]}`, display: "flex", alignItems: "center",
        justifyContent: "center", fontSize: 16, flexShrink: 0 }}>
        {TYPE_ICON[host.type]}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: WHITE, fontSize: 13, fontWeight: 600, marginBottom: 2,
          whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{host.name}</div>
        <div style={{ color: DIM, fontSize: 11, fontFamily: "'Courier New', monospace" }}>{host.ip}  ·  {host.vendor}</div>
      </div>
      <div style={{ flexShrink: 0 }}><RiskBadge risk={host.risk} /></div>
    </div>
  );
}

function Row({ label, value, last }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", paddingBottom: last ? 0 : 8,
      marginBottom: last ? 0 : 8, borderBottom: last ? "none" : "1px solid #2a2d4a" }}>
      <span style={{ color: DIM, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.8 }}>{label}</span>
      <span style={{ color: WHITE, fontSize: 12, fontFamily: "'Courier New', monospace" }}>{value}</span>
    </div>
  );
}
const PORT_SERVICE = {
  21: 'ftp', 22: 'openssh', 23: 'telnet', 25: 'smtp',
  80: 'apache http', 139: 'netbios', 443: 'openssl',
  445: 'samba smb', 3389: 'windows rdp', 4444: 'metasploit',
  5900: 'vnc', 8080: 'apache tomcat', 8443: 'https', 8888: 'http'
}

function useCVEs(ports) {
  const [cves, setCves] = useState({})
  useEffect(() => {
    if (!ports || ports.length === 0) return
    ports.forEach(port => {
      const service = PORT_SERVICE[port]
      if (!service) return
      fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(service)}&resultsPerPage=5`)
        .then(r => r.json())
        .then(data => {
          const items = data.vulnerabilities || []
          const critical = items.filter(v => {
            const score = v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
            return score >= 9.0
          }).length
          const high = items.filter(v => {
            const score = v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
            return score >= 7.0 && score < 9.0
          }).length
          setCves(prev => ({ ...prev, [port]: { total: items.length, critical, high } }))
        })
        .catch(() => {})
    })
  }, [ports?.join(',')])
  return cves
}
function HostDetail({ host }) {
  const cves = useCVEs(host?.ports)
  if (!host) return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      height: "100%", color: DIM, gap: 12 }}>
      <div style={{ fontSize: 48, opacity: 0.3 }}>◈</div>
      <div style={{ fontSize: 13 }}>Select a host to view details</div>
    </div>
  );
  return (
    <div style={{ padding: 24, overflowY: "auto", height: "100%" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 24 }}>
        <div style={{ width: 48, height: 48, borderRadius: "50%", background: "#1a1d35",
          border: `2px solid ${RISK_COLOR[host.risk]}`, display: "flex", alignItems: "center",
          justifyContent: "center", fontSize: 24, flexShrink: 0 }}>
          {TYPE_ICON[host.type]}
        </div>
        <div>
          <div style={{ color: WHITE, fontSize: 17, fontWeight: 700 }}>{host.name}</div>
          <div style={{ color: DIM, fontSize: 12, fontFamily: "'Courier New', monospace", marginTop: 3 }}>
            {host.ip}  ·  {host.mac}
          </div>
          <div style={{ marginTop: 6 }}><RiskBadge risk={host.risk} /></div>
        </div>
      </div>
      <div style={{ background: "#1a1d35", borderRadius: 6, padding: 14, marginBottom: 16 }}>
        <Row label="Vendor" value={host.vendor} />
        <Row label="Device Type" value={host.type.toUpperCase()} />
        <Row label="Open Ports" value={host.ports.length ? host.ports.join(", ") : "None detected"} />
        <Row label="MAC Address" value={host.mac} last />
      </div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ color: GOLD, fontSize: 11, fontWeight: 700, letterSpacing: 1.5,
          textTransform: "uppercase", marginBottom: 10 }}>Findings</div>
        {host.issues.map((issue, i) => (
          <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
            <span style={{ color: RISK_COLOR[host.risk], marginTop: 1, flexShrink: 0 }}>▸</span>
            <span style={{ color: "#c8cfe8", fontSize: 12, lineHeight: 1.5 }}>{issue}</span>
          </div>
        ))}
        {host.ports.length > 0 && (
  <div style={{ marginBottom: 16 }}>
    <div style={{ color: TEAL, fontSize: 11, fontWeight: 700, letterSpacing: 1.5,
      textTransform: "uppercase", marginBottom: 10 }}>CVE Intelligence</div>
    {host.ports.map(port => (
      <div key={port} style={{ display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: 8, background: "#1a1d35",
        borderRadius: 5, padding: "8px 12px" }}>
        <span style={{ color: WHITE, fontSize: 12, fontFamily: "'Courier New', monospace" }}>
          Port {port} — {PORT_SERVICE[port] || 'unknown'}
        </span>
        {cves[port] ? (
          <span style={{ fontSize: 11, color: cves[port].critical > 0 ? "#ff4444" :
            cves[port].high > 0 ? GOLD : TEAL }}>
            {cves[port].critical > 0 ? `⚠ ${cves[port].critical} critical CVEs` :
             cves[port].high > 0 ? `▲ ${cves[port].high} high CVEs` :
             `✓ ${cves[port].total} CVEs found`}
          </span>
        ) : (
          <span style={{ fontSize: 11, color: DIM }}>Looking up...</span>
        )}
      </div>
    ))}
  </div>
)}
      </div>
      <div style={{ background: "linear-gradient(135deg, #1a1d35 0%, #12142a 100%)",
        border: `1px solid ${GOLD}40`, borderRadius: 6, padding: 14, marginTop: 20 }}>
        <div style={{ color: GOLD, fontSize: 11, fontWeight: 700, letterSpacing: 1, marginBottom: 6 }}>
          BRAVO SIX RECOMMENDS
        </div>
        <div style={{ color: "#c8cfe8", fontSize: 12, lineHeight: 1.6, marginBottom: 12 }}>
          {host.risk === "high"
            ? "This device has critical exposure. A Bravo Six professional assessment will remediate these findings."
            : host.risk === "medium"
            ? "This device has moderate exposure. Our team can implement fixes and establish monitoring."
            : "This device appears healthy. Our assessment confirms your security posture for this host."}
        </div>
        <button style={{ background: GOLD, color: NAVY, border: "none", borderRadius: 5,
  padding: "10px 22px", fontSize: 13, fontWeight: 800, cursor: "pointer" }}
  onClick={() => window.bscScout.openExternal('https://bravosixcyber.com/contact')}>
  Book a Free Consultation
</button>
<button style={{ background: "transparent", color: GOLD, border: `1px solid ${GOLD}`,
  borderRadius: 5, padding: "10px 22px", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
  onClick={() => window.bscScout.openExternal('https://bravosixcyber.com')}>
  bravosixcyber.com →
</button>
      </div>
    </div>
  );
}

function ReportScreen({ hosts, onBack }) {
  const high   = hosts.filter(h => h.risk === "high").length;
  const medium = hosts.filter(h => h.risk === "medium").length;
  const low    = hosts.filter(h => h.risk === "low").length;
  const score  = Math.max(0, 100 - high * 22 - medium * 9 - low * 2);
  const grade  = score >= 80 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const gradeColor = score >= 80 ? "#2ecc71" : score >= 60 ? "#f39c12" : "#e74c3c";
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "32px 40px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 32 }}>
        <div>
          <div style={{ color: GOLD, fontSize: 11, fontWeight: 700, letterSpacing: 2,
            textTransform: "uppercase", marginBottom: 6 }}>Network Security Assessment Report</div>
          <div style={{ color: WHITE, fontSize: 22, fontWeight: 700 }}>Home / Small Business Network</div>
          <div style={{ color: DIM, fontSize: 12, marginTop: 4 }}>
            Scan completed {new Date().toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}
          </div>
        </div>
        <button onClick={onBack} style={{ background: "transparent", border: `1px solid #2a2d4a`,
          color: DIM, borderRadius: 4, padding: "6px 14px", cursor: "pointer", fontSize: 12 }}>
          ← Back to Results
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16, marginBottom: 32 }}>
        {[
          { label: "Security Score", value: `${score}/100`, sub: `Grade: ${grade}`, color: gradeColor },
          { label: "Hosts Discovered", value: hosts.length, sub: "devices on network", color: TEAL },
          { label: "High Risk", value: high, sub: "require immediate action", color: "#e74c3c" },
          { label: "Medium Risk", value: medium, sub: "should be addressed", color: "#f39c12" },
        ].map((c, i) => (
          <div key={i} style={{ background: "#12142a", border: `1px solid #2a2d4a`, borderRadius: 8, padding: 20, textAlign: "center" }}>
            <div style={{ color: c.color, fontSize: 28, fontWeight: 800, marginBottom: 4 }}>{c.value}</div>
            <div style={{ color: WHITE, fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{c.label}</div>
            <div style={{ color: DIM, fontSize: 11 }}>{c.sub}</div>
          </div>
        ))}
      </div>
      <div style={{ marginBottom: 32 }}>
        <div style={{ color: GOLD, fontSize: 11, fontWeight: 700, letterSpacing: 2,
          textTransform: "uppercase", marginBottom: 14 }}>All Discovered Hosts</div>
        <div style={{ border: "1px solid #2a2d4a", borderRadius: 8, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "140px 200px 1fr 80px",
            background: "#1a1d35", padding: "10px 16px", borderBottom: "1px solid #2a2d4a" }}>
            {["IP Address","Device","Findings","Risk"].map(h => (
              <div key={h} style={{ color: DIM, fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>{h}</div>
            ))}
          </div>
          {hosts.map((h, i) => (
            <div key={h.ip} style={{ display: "grid", gridTemplateColumns: "140px 200px 1fr 80px",
              padding: "12px 16px", borderBottom: i < hosts.length-1 ? "1px solid #1e2040" : "none",
              background: i % 2 === 0 ? "#12142a" : "#0f1228" }}>
              <div style={{ color: TEAL, fontFamily: "'Courier New', monospace", fontSize: 12 }}>{h.ip}</div>
              <div style={{ color: WHITE, fontSize: 12 }}>{h.name}</div>
              <div style={{ color: DIM, fontSize: 11 }}>{h.issues[0]}{h.issues.length > 1 ? ` +${h.issues.length-1} more` : ""}</div>
              <RiskBadge risk={h.risk} />
            </div>
          ))}
        </div>
      </div>
      <div style={{ background: `linear-gradient(135deg, ${NAVY} 0%, #1e2048 100%)`,
        border: `1px solid ${GOLD}`, borderRadius: 10, padding: 28 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 24 }}>
          <div style={{ flex: 1 }}>
            <div style={{ color: GOLD, fontSize: 13, fontWeight: 800, letterSpacing: 1.5,
              textTransform: "uppercase", marginBottom: 8 }}>BRAVO SIX CYBER LLC</div>
            <div style={{ color: WHITE, fontSize: 18, fontWeight: 700, marginBottom: 8, lineHeight: 1.4 }}>
              {high > 0 ? `${high} critical ${high === 1 ? "issue" : "issues"} found. Professional remediation recommended.`
                : "Let our team provide a full professional assessment."}
            </div>
            <div style={{ color: "#a0aac0", fontSize: 13, lineHeight: 1.7, marginBottom: 16 }}>
              This automated scan identifies surface-level exposure. A Bravo Six certified assessment
              (CISSP · CICP · SDVOSB) goes deeper — credentialed scanning, configuration review,
              policy analysis, and a written remediation roadmap.
            </div>
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
              <button style={{ background: GOLD, color: NAVY, border: "none", borderRadius: 5,
                padding: "10px 22px", fontSize: 13, fontWeight: 800, cursor: "pointer" }}>
                Book a Free Consultation
              </button>
              <button style={{ background: "transparent", color: GOLD, border: `1px solid ${GOLD}`,
                borderRadius: 5, padding: "10px 22px", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>
                bravosixcyber.com →
              </button>
            </div>
          </div>
          <div style={{ flexShrink: 0, textAlign: "center", background: "#0f1228",
            border: "1px solid #2a2d4a", borderRadius: 8, padding: "16px 20px" }}>
            <div style={{ color: DIM, fontSize: 10, letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>Contact</div>
            <div style={{ color: WHITE, fontSize: 12, marginBottom: 4 }}>info@bravosixcyber.com</div>
            <div style={{ color: WHITE, fontSize: 12, marginBottom: 4 }}>656.245.8307</div>
            <div style={{ color: TEAL, fontSize: 12 }}>SDVOSB · CISSP · CICP</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [screen, setScreen] = useState("home");
  const [scanLines, setScanLines] = useState([]);
  const [progress, setProgress] = useState(0);
  const [hosts, setHosts] = useState([]);
  const [selectedHost, setSelectedHost] = useState(null);
  const [scanType, setScanType] = useState("quick");
  const [subnet, setSubnet] = useState("192.168.1.0/24");

  useEffect(() => {
    if (window.bscScout && window.bscScout.detectSubnet) {
      window.bscScout.detectSubnet().then(detected => {
        if (detected) setSubnet(detected);
      }).catch(() => {});
    }
  }, []);
  const termRef = useRef(null);

  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight; }, [scanLines]);

  async function startScan() {
    setScreen("scanning");
    setScanLines([]);
    setProgress(0);
    setHosts([]);

    const addLine = (text, color = GOLD) => {
      setScanLines(prev => [...prev, { text, color }]);
    };

    addLine(`[BSC-SCOUT] Initializing scan engine v1.0.4`, TEAL);
    await sleep(300);
    addLine(`[CONFIG]    Subnet: ${subnet}`, DIM);
    await sleep(300);
    addLine(`[CONFIG]    Scan type: ${scanType.toUpperCase()}`, DIM);
    await sleep(400);
    setProgress(5);

    try {
      if (window.bscScout && window.bscScout.startScan) {
        addLine(`[ARP]       Broadcasting ARP requests on ${subnet}...`, TEAL);
        setProgress(10);

        window.bscScout.onScanProgress((data) => {
          if (data.phase === "ping") {
            addLine(`[PING]      Sweeping ${subnet} for live hosts...`, TEAL);
            setProgress(20);
          } else if (data.phase === "arp") {
            addLine(`[ARP]       ${data.found} hosts found — reading MAC addresses...`, "#7fdbff");
            setProgress(40);
          } else if (data.phase === "ports") {
            addLine(`[PORT]      Scanning ports on ${data.found} hosts...`, TEAL);
            setProgress(50);
          } else if (data.phase === "host-done") {
            const riskColor = data.risk === "high" ? "#e74c3c" : data.risk === "medium" ? "#f39c12" : "#2ecc71";
            const prefix = data.risk === "high" ? "[CRIT]" : data.risk === "medium" ? "[WARN]" : "[OK]  ";
            addLine(`${prefix}      ${data.ip}  →  ${data.risk} risk`, riskColor);
          }
        });

        const results = await window.bscScout.startScan(subnet);
        window.bscScout.removeScanProgress();

        setProgress(90);

        if (results.length === 0) {
          addLine(`[WARN]      No hosts found on ${subnet}`, "#f39c12");
          addLine(`[TIP]       Try checking your subnet range`, DIM);
          setProgress(100);
          await sleep(1500);
          setScreen("results");
          return;
        }

        const high = results.filter(h => h.risk === "high").length;
        const medium = results.filter(h => h.risk === "medium").length;
        addLine(`[DONE]      Scan complete — ${results.length} hosts, ${high} high risk, ${medium} medium risk`, "#2ecc71");
        await sleep(300);
        addLine(`[BSC]       Generating report...`, GOLD);
        setProgress(100);

        for (const host of results) {
          await sleep(150);
          setHosts(prev => [...prev, host]);
        }

        await sleep(600);
        setScreen("results");

      } else {
        // Demo mode fallback
        const lines = [
          { t:0,    color:TEAL,       text:`[DEMO]      Running in demo mode` },
          { t:500,  color:"#7fdbff",  text:`[DISCO]     Host found → 192.168.1.1   (Netgear)` },
          { t:900,  color:"#7fdbff",  text:`[DISCO]     Host found → 192.168.1.10  (Raspberry Pi)` },
          { t:1300, color:"#7fdbff",  text:`[DISCO]     Host found → 192.168.1.15  (Apple)` },
          { t:1700, color:"#7fdbff",  text:`[DISCO]     Host found → 192.168.1.20  (Samsung)` },
          { t:2100, color:"#7fdbff",  text:`[DISCO]     Host found → 192.168.1.25  (Nest Labs)` },
          { t:2500, color:"#7fdbff",  text:`[DISCO]     Host found → 192.168.1.30  (Dell)` },
          { t:2900, color:"#e74c3c",  text:`[CRIT]      192.168.1.30 → port 3389 open (RDP)` },
          { t:3300, color:"#e74c3c",  text:`[CRIT]      192.168.1.10 → port 5900 open (VNC)` },
          { t:3700, color:"#f39c12",  text:`[WARN]      192.168.1.1  → port 22 open (SSH)` },
          { t:4100, color:TEAL,       text:`[RISK]      Calculating risk scores...` },
          { t:4500, color:"#2ecc71",  text:`[DONE]      Scan complete — demo data loaded` },
          { t:4800, color:GOLD,       text:`[BSC]       Generating report...` },
        ];
        for (let i = 0; i < lines.length; i++) {
          await sleep(i===0 ? 0 : lines[i].t - lines[i-1].t);
          setScanLines(prev => [...prev, lines[i]]);
          setProgress(Math.round((i/(lines.length-1))*100));
        }
        for (let i = 0; i < FAKE_HOSTS.length; i++) {
          await sleep(300);
          setHosts(prev => [...prev, FAKE_HOSTS[i]]);
        }
        await sleep(600);
        setScreen("results");
      }

    } catch (err) {
      addLine(`[ERROR]     Scan failed: ${err.message}`, "#e74c3c");
      addLine(`[TIP]       Check network connection and try again`, DIM);
      setProgress(100);
      await sleep(2000);
      setScreen("results");
    }
  }

  if (screen === "home") return (
    <div style={{ minHeight:"100vh", background:NAVY2, display:"flex", flexDirection:"column",
      fontFamily:"'Segoe UI', system-ui, sans-serif", color:WHITE }}>
      <div style={{ background:NAVY, borderBottom:"1px solid #2a2d4a", padding:"12px 28px",
        display:"flex", alignItems:"center", gap:16 }}>
        <div style={{ width:32, height:32, borderRadius:6, background:GOLD,
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>⬡</div>
        <div>
          <div style={{ fontSize:13, fontWeight:700, color:WHITE }}>BSC Network Scout</div>
          <div style={{ fontSize:10, color:DIM }}>by Bravo Six Cyber LLC · SDVOSB</div>
        </div>
      </div>
      <div style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center",
        justifyContent:"center", padding:"48px 40px", textAlign:"center" }}>
        <img src="./bsc-logo.png" alt="Bravo Six Cyber"
          style={{ width:200, height:200, objectFit:"contain", marginBottom:24 }} />
        <div style={{ color:GOLD, fontSize:11, fontWeight:700, letterSpacing:3,
          textTransform:"uppercase", marginBottom:12 }}>Bravo Six Cyber LLC</div>
        <h1 style={{ fontSize:36, fontWeight:800, margin:0, marginBottom:10,
          background:`linear-gradient(135deg, ${WHITE} 40%, ${TEAL} 100%)`,
          WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent" }}>BSC Network Scout</h1>
        <p style={{ color:DIM, fontSize:15, maxWidth:480, lineHeight:1.7, margin:"0 0 40px" }}>
          Scan your home or small business network for exposed devices, open ports,
          and security vulnerabilities — then get expert help from a certified cybersecurity professional.
        </p>
        <div style={{ background:NAVY, border:"1px solid #2a2d4a", borderRadius:10,
          padding:28, width:"100%", maxWidth:480, textAlign:"left", marginBottom:24 }}>
          <div style={{ marginBottom:20 }}>
            <label style={{ color:DIM, fontSize:11, fontWeight:600, letterSpacing:1,
              textTransform:"uppercase", display:"block", marginBottom:8 }}>Network Range</label>
            <input value={subnet} onChange={e => setSubnet(e.target.value)}
              style={{ width:"100%", background:"#12142a", border:"1px solid #2a2d4a",
                borderRadius:5, padding:"9px 12px", color:TEAL, fontFamily:"'Courier New', monospace",
                fontSize:13, outline:"none", boxSizing:"border-box" }} />
          </div>
          <div>
            <label style={{ color:DIM, fontSize:11, fontWeight:600, letterSpacing:1,
              textTransform:"uppercase", display:"block", marginBottom:8 }}>Scan Type</label>
            <div style={{ display:"flex", gap:10 }}>
              {[["quick","Quick Scan","~2 min"],["full","Full Scan","~8 min"]].map(([val,label,time]) => (
                <button key={val} onClick={() => setScanType(val)}
                  style={{ flex:1, background:scanType===val?`${TEAL}15`:"#12142a",
                    border:`1px solid ${scanType===val?TEAL:"#2a2d4a"}`,
                    borderRadius:6, padding:"10px 8px", cursor:"pointer", textAlign:"center" }}>
                  <div style={{ color:scanType===val?TEAL:WHITE, fontSize:12, fontWeight:600 }}>{label}</div>
                  <div style={{ color:DIM, fontSize:10, marginTop:2 }}>{time}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
        <button onClick={startScan}
          style={{ background:`linear-gradient(135deg, ${GOLD} 0%, #a07830 100%)`,
            color:NAVY, border:"none", borderRadius:8, padding:"14px 48px",
            fontSize:15, fontWeight:800, cursor:"pointer", letterSpacing:0.5,
            boxShadow:`0 4px 20px ${GOLD}40` }}>
          ▶  Start Network Scan
        </button>
        <div style={{ display:"flex", gap:24, marginTop:32, flexWrap:"wrap", justifyContent:"center" }}>
          {["CISSP Certified","SDVOSB Certified","No Data Leaves Your Device","Veteran-Owned"].map(t => (
            <div key={t} style={{ display:"flex", alignItems:"center", gap:6, color:DIM, fontSize:11 }}>
              <span style={{ color:"#2ecc71" }}>✓</span> {t}
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  if (screen === "scanning") return (
    <div style={{ minHeight:"100vh", background:NAVY2, display:"flex", flexDirection:"column",
      fontFamily:"'Segoe UI', system-ui, sans-serif", color:WHITE }}>
      <div style={{ background:NAVY, borderBottom:"1px solid #2a2d4a", padding:"12px 28px",
        display:"flex", alignItems:"center", gap:16 }}>
        <div style={{ width:32, height:32, borderRadius:6, background:GOLD,
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>⬡</div>
        <div>
          <div style={{ fontSize:13, fontWeight:700 }}>BSC Network Scout</div>
          <div style={{ fontSize:10, color:DIM }}>by Bravo Six Cyber LLC · SDVOSB</div>
        </div>
        <div style={{ marginLeft:"auto", background:`${TEAL}15`, border:`1px solid ${TEAL}40`,
          borderRadius:20, padding:"4px 14px", display:"flex", alignItems:"center", gap:8 }}>
          <div style={{ width:7, height:7, borderRadius:"50%", background:TEAL }} />
          <span style={{ color:TEAL, fontSize:11, fontWeight:600 }}>SCANNING</span>
        </div>
      </div>
      <div style={{ flex:1, display:"flex", gap:0 }}>
        <div style={{ flex:1, display:"flex", flexDirection:"column", padding:24 }}>
          <div style={{ color:GOLD, fontSize:11, fontWeight:700, letterSpacing:2,
            textTransform:"uppercase", marginBottom:12 }}>Scan Output</div>
          <div ref={termRef} style={{ flex:1, background:"#080a1a", border:"1px solid #1a1d35",
            borderRadius:8, padding:16, overflowY:"auto", fontFamily:"'Courier New', monospace" }}>
            {scanLines.map((l,i) => (
              <div key={i} style={{ color:l.color, fontSize:11, lineHeight:2 }}>{l.text}</div>
            ))}
          </div>
          <div style={{ marginTop:16 }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
              <span style={{ color:DIM, fontSize:11 }}>Progress</span>
              <span style={{ color:TEAL, fontSize:11, fontFamily:"'Courier New', monospace" }}>{progress}%</span>
            </div>
            <div style={{ background:"#1a1d35", borderRadius:4, height:6, overflow:"hidden" }}>
              <div style={{ background:`linear-gradient(90deg, ${TEAL}, ${GOLD})`,
                height:"100%", width:`${progress}%`, transition:"width 0.4s", borderRadius:4 }} />
            </div>
          </div>
        </div>
        <div style={{ width:280, background:NAVY, borderLeft:"1px solid #2a2d4a", padding:20, overflowY:"auto" }}>
          <div style={{ color:GOLD, fontSize:11, fontWeight:700, letterSpacing:2,
            textTransform:"uppercase", marginBottom:14 }}>Hosts Found ({hosts.length})</div>
          {hosts.map(h => (
            <div key={h.ip} style={{ background:"#12142a", border:`1px solid #2a2d4a`,
              borderRadius:5, padding:"8px 12px", marginBottom:6,
              display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <div>
                <div style={{ color:TEAL, fontFamily:"'Courier New', monospace", fontSize:11 }}>{h.ip}</div>
                <div style={{ color:DIM, fontSize:10, marginTop:1 }}>{h.vendor}</div>
              </div>
              <RiskBadge risk={h.risk} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  if (screen === "results") return (
    <div style={{ height:"100vh", background:NAVY2, display:"flex", flexDirection:"column",
      fontFamily:"'Segoe UI', system-ui, sans-serif", color:WHITE, overflow:"hidden" }}>
      <div style={{ background:NAVY, borderBottom:"1px solid #2a2d4a", padding:"10px 20px",
        display:"flex", alignItems:"center", gap:16, flexShrink:0 }}>
        <div style={{ width:28, height:28, borderRadius:5, background:GOLD,
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>⬡</div>
        <div>
          <div style={{ fontSize:12, fontWeight:700 }}>BSC Network Scout</div>
          <div style={{ fontSize:10, color:DIM }}>Bravo Six Cyber LLC · SDVOSB</div>
        </div>
        <div style={{ marginLeft:20, display:"flex", gap:10 }}>
          {[
            { label:`${hosts.filter(h=>h.risk==="high").length} High`, color:"#e74c3c" },
            { label:`${hosts.filter(h=>h.risk==="medium").length} Medium`, color:"#f39c12" },
            { label:`${hosts.filter(h=>h.risk==="low").length} Low`, color:"#2ecc71" },
          ].map(p => (
            <div key={p.label} style={{ background:`${p.color}15`, border:`1px solid ${p.color}40`,
              borderRadius:20, padding:"3px 12px", color:p.color, fontSize:11, fontWeight:600 }}>
              {p.label}
            </div>
          ))}
        </div>
        <div style={{ marginLeft:"auto", display:"flex", gap:10 }}>
          <button onClick={() => setScreen("report")}
            style={{ background:GOLD, color:NAVY, border:"none", borderRadius:5,
              padding:"6px 16px", fontSize:12, fontWeight:700, cursor:"pointer" }}>
            View Full Report →
          </button>
          <button onClick={async () => {
            if (window.bscScout && window.bscScout.generatePdf) {
              const result = await window.bscScout.generatePdf({ hosts, subnet });
              if (result.success) alert(`Report saved to: ${result.filePath}`);
              else if (result.reason !== 'canceled') alert(`Error: ${result.reason}`);
            }
          }}
            style={{ background:"transparent", border:`1px solid ${GOLD}`, color:GOLD,
              borderRadius:5, padding:"6px 14px", fontSize:12, fontWeight:600, cursor:"pointer" }}>
            Save PDF Report
          </button>
          <button onClick={() => setScreen("home")}
            style={{ background:"transparent", border:"1px solid #2a2d4a", color:DIM,
              borderRadius:5, padding:"6px 14px", fontSize:12, cursor:"pointer" }}>
            New Scan
          </button>
        </div>
      </div>
      <div style={{ flex:1, display:"flex", overflow:"hidden" }}>
        <div style={{ width:300, background:NAVY, borderRight:"1px solid #2a2d4a",
          display:"flex", flexDirection:"column", overflow:"hidden" }}>
          <div style={{ padding:"14px 16px", borderBottom:"1px solid #2a2d4a", flexShrink:0 }}>
            <div style={{ color:GOLD, fontSize:10, fontWeight:700, letterSpacing:1.5,
              textTransform:"uppercase", marginBottom:4 }}>Discovered Hosts</div>
            <div style={{ color:DIM, fontSize:11 }}>{hosts.length} devices on {subnet}</div>
          </div>
          <div style={{ flex:1, overflowY:"auto", padding:"12px 12px" }}>
            {hosts.map(h => <HostCard key={h.ip} host={h} onClick={setSelectedHost} selected={selectedHost?.ip===h.ip} />)}
          </div>
        </div>
        <div style={{ flex:1, background:NAVY2, overflow:"hidden" }}>
          <HostDetail host={selectedHost} />
        </div>
        <div style={{ width:220, background:NAVY, borderLeft:"1px solid #2a2d4a", padding:16, overflowY:"auto" }}>
          <div style={{ color:GOLD, fontSize:10, fontWeight:700, letterSpacing:1.5,
            textTransform:"uppercase", marginBottom:14 }}>Risk Summary</div>
          {["high","medium","low"].map(r => {
            const rHosts = hosts.filter(h => h.risk===r);
            return (
              <div key={r} style={{ marginBottom:16 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                  <span style={{ color:RISK_COLOR[r], fontSize:11, fontWeight:700, textTransform:"uppercase" }}>{r}</span>
                  <span style={{ color:WHITE, fontSize:11, fontWeight:700 }}>{rHosts.length}</span>
                </div>
                {rHosts.map(h => (
                  <div key={h.ip} onClick={() => setSelectedHost(h)}
                    style={{ background:RISK_BG[r], border:`1px solid ${RISK_COLOR[r]}30`,
                      borderRadius:4, padding:"5px 8px", marginBottom:4, cursor:"pointer" }}>
                    <div style={{ color:WHITE, fontSize:10, fontWeight:600 }}>{h.name}</div>
                    <div style={{ color:DIM, fontSize:10, fontFamily:"'Courier New', monospace" }}>{h.ip}</div>
                  </div>
                ))}
              </div>
            );
          })}
          <div style={{ marginTop:20, background:`${GOLD}10`, border:`1px solid ${GOLD}30`,
            borderRadius:6, padding:12 }}>
            <div style={{ color:GOLD, fontSize:10, fontWeight:700, letterSpacing:1,
              textTransform:"uppercase", marginBottom:6 }}>Need Help?</div>
            <div style={{ color:DIM, fontSize:10, lineHeight:1.6, marginBottom:10 }}>
              Bravo Six Cyber provides certified professional remediation for all findings.
            </div>
            <button onClick={() => setScreen("report")}
              style={{ width:"100%", background:GOLD, color:NAVY, border:"none",
                borderRadius:4, padding:"7px 0", fontSize:11, fontWeight:700, cursor:"pointer" }}>
              Get Expert Help
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  if (screen === "report") return (
    <div style={{ height:"100vh", background:NAVY2, display:"flex", flexDirection:"column",
      fontFamily:"'Segoe UI', system-ui, sans-serif", color:WHITE, overflow:"hidden" }}>
      <div style={{ background:NAVY, borderBottom:"1px solid #2a2d4a", padding:"10px 20px",
        display:"flex", alignItems:"center", gap:16, flexShrink:0 }}>
        <div style={{ width:28, height:28, borderRadius:5, background:GOLD,
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>⬡</div>
        <div>
          <div style={{ fontSize:12, fontWeight:700 }}>BSC Network Scout — Report</div>
          <div style={{ fontSize:10, color:DIM }}>Bravo Six Cyber LLC · SDVOSB</div>
        </div>
      </div>
      <ReportScreen hosts={hosts} onBack={() => setScreen("results")} />
    </div>
  );

  return null;
}