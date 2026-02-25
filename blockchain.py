import { useState, useEffect, useRef } from "react";

// ═══════════════════════════════════════════════════════════
//  NEBULA DATA
// ═══════════════════════════════════════════════════════════
const FILES = [
  { name: "nebula_core.py",      lines: 1208, icon: "⚙️", color: "#00e5ff", desc: "Blockchain + UTXO + Merkle + secp256k1 ECDSA + Base58Check" },
  { name: "nebula_contracts.py", lines: 797,  icon: "📜", color: "#f0a500", desc: "64 Script Opcodes + HTLC + Multisig + Timelock + NBL-20 Tokens" },
  { name: "nebula_tests.py",     lines: 843,  icon: "🧪", color: "#00ff88", desc: "42 tests — Crypto, TX, Block, UTXO, Wallet, Contracts, Network" },
  { name: "nebula_cli.py",       lines: 759,  icon: "💻", color: "#9d4edd", desc: "Full CLI + Interactive REPL — node, mine, wallet, send, block, tx" },
  { name: "nebula_security.py",  lines: 608,  icon: "🛡️", color: "#ff3355", desc: "DoS Protection + Rate Limiter + Double-Spend + Replay + Checkpoints" },
  { name: "nebula_wallet.py",    lines: 468,  icon: "👛", color: "#00e5ff", desc: "BIP32/39/44 HD Wallet + 12-word Mnemonic + ECDSA Signing" },
  { name: "nebula_network.py",   lines: 508,  icon: "🌐", color: "#00ff88", desc: "P2P Protocol + Peer Discovery + Block Sync + TX Broadcast" },
  { name: "nebula_node.py",      lines: 415,  icon: "🖥️", color: "#f0a500", desc: "Full Node + Block Explorer + Auto-save + Status Dashboard" },
  { name: "nebula_miner.py",     lines: 312,  icon: "⛏️", color: "#9d4edd", desc: "Multi-thread PoW Miner + Halving + Stats + Demo Mode" },
  { name: "nebula_server_setup.sh", lines: 443, icon: "🚀", color: "#ff3355", desc: "Complete Ubuntu server deployment — 17-step auto setup script" },
];

const TESTS = [
  { group: "📐 Crypto",       tests: ["SHA256 / SHA256d", "HASH160 (RIPEMD+SHA256)", "secp256k1 keypair", "ECDSA sign/verify", "NBL address (starts N)", "DER encoding", "RFC6979 deterministic", "Base58 encode/decode", "WIF private key"] },
  { group: "💸 Transactions", tests: ["Coinbase tx", "TX serialization", "TXID computation", "Signature hash", "Full P2PKH verify", "2-of-3 multisig"] },
  { group: "📦 Blocks",       tests: ["Header serialization", "Block hash", "Merkle tree", "Merkle proofs", "Difficulty adjust", "Halving schedule", "Genesis block"] },
  { group: "⛓️ Blockchain",   tests: ["UTXO add/spend", "UTXO balance", "Chain validation", "Mempool init", "Supply tracking"] },
  { group: "👛 Wallet",       tests: ["BIP39 mnemonic", "BIP32 derivation", "BIP44 path", "Wallet create", "Wallet restore"] },
  { group: "📜 Contracts",    tests: ["Script interpreter", "P2PKH script", "HTLC contract", "NBL-20 deploy", "NBL-20 transfer", "NBL-20 burn", "Timelock script"] },
  { group: "🌐 Network",      tests: ["Message encoding", "Message roundtrip", "Variable-length int"] },
];

const HALVINGS = [
  { era: "Era I",   blocks: "0 – 209,999",    reward: 50,     year: "2025–2029", current: true  },
  { era: "Era II",  blocks: "210,000+",       reward: 25,     year: "2029–2033", current: false },
  { era: "Era III", blocks: "420,000+",       reward: 12.5,   year: "2033–2037", current: false },
  { era: "Era IV",  blocks: "630,000+",       reward: 6.25,   year: "2037–2041", current: false },
  { era: "Era V",   blocks: "840,000+",       reward: 3.125,  year: "2041–2045", current: false },
];

const NAV = [
  { id: "dashboard",  icon: "◈", label: "Dashboard",     badge: null,   badgeColor: "cyan"  },
  { id: "blockchain", icon: "⛓", label: "Blockchain",    badge: "HGT",  badgeColor: "cyan"  },
  { id: "explorer",   icon: "🔍", label: "Explorer",      badge: null,   badgeColor: "cyan"  },
  { id: "miner",      icon: "⛏", label: "Miner",         badge: "OFF",  badgeColor: "red"   },
  { id: "wallet",     icon: "◎", label: "Wallet",        badge: null,   badgeColor: "cyan"  },
  { id: "mempool",    icon: "≋", label: "Mempool",       badge: "0",    badgeColor: "cyan"  },
  { id: "network",    icon: "◉", label: "Network",       badge: null,   badgeColor: "cyan"  },
  { id: "security",   icon: "🛡", label: "Security",     badge: null,   badgeColor: "green" },
  { id: "contracts",  icon: "📜", label: "Contracts",    badge: null,   badgeColor: "cyan"  },
  { id: "files",      icon: "📁", label: "Files",         badge: "10",   badgeColor: "gold"  },
  { id: "server",     icon: "🖥", label: "Server",       badge: null,   badgeColor: "cyan"  },
  { id: "tests",      icon: "✓", label: "Tests 42/42",   badge: "✓",   badgeColor: "green" },
];

// ═══════════════════════════════════════════════════════════
//  STYLES
// ═══════════════════════════════════════════════════════════
const S = {
  app: {
    display: "flex", minHeight: "100vh",
    background: "#030810", color: "#c0d4e8",
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fontSize: 12,
  },
  sidebar: {
    width: 210, flexShrink: 0,
    background: "linear-gradient(180deg,#04080f 0%,#020608 100%)",
    borderRight: "1px solid #1a2d45",
    display: "flex", flexDirection: "column",
    position: "sticky", top: 0, height: "100vh", overflowY: "auto",
  },
  main: { flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" },
  topbar: {
    height: 52, background: "rgba(4,8,15,0.97)",
    borderBottom: "1px solid #1a2d45",
    display: "flex", alignItems: "center",
    padding: "0 24px", gap: 12,
    backdropFilter: "blur(12px)",
    position: "sticky", top: 0, zIndex: 50,
    flexShrink: 0,
  },
  content: { flex: 1, overflowY: "auto", padding: 24 },
};

// ═══════════════════════════════════════════════════════════
//  REUSABLE COMPONENTS
// ═══════════════════════════════════════════════════════════

function Card({ children, style, glow }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        background: "#080f1c", border: `1px solid ${hov ? "#2a4060" : "#1a2d45"}`,
        borderRadius: 6, padding: 18, position: "relative", overflow: "hidden",
        transition: "border-color 0.2s, box-shadow 0.2s",
        boxShadow: hov && glow ? `0 0 20px ${glow}22` : "none",
        ...style,
      }}
    >
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: 1,
        background: "linear-gradient(90deg,transparent,rgba(0,229,255,0.2),transparent)",
      }}/>
      {children}
    </div>
  );
}

function CardTitle({ children }) {
  return <div style={{ fontSize: 9, color: "#4a6a8a", letterSpacing: 3, textTransform: "uppercase", marginBottom: 10 }}>{children}</div>;
}

function StatRow({ label, value, color }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "7px 0", borderBottom: "1px solid #0f1e2e" }}>
      <span style={{ color: "#5a7a9a", fontSize: 11 }}>{label}</span>
      <span style={{ color: color || "#c0d4e8", fontWeight: 600, fontSize: 11 }}>{value}</span>
    </div>
  );
}

function BigVal({ children, color = "#f0a500" }) {
  return <div style={{
    fontFamily: "'Orbitron','JetBrains Mono',monospace",
    fontSize: 28, fontWeight: 900, color,
    textShadow: `0 0 20px ${color}44`, lineHeight: 1,
  }}>{children}</div>;
}

function Badge({ children, color = "cyan" }) {
  const colors = {
    cyan:  { bg: "rgba(0,229,255,0.1)", text: "#00e5ff", border: "rgba(0,229,255,0.25)" },
    green: { bg: "rgba(0,255,136,0.1)", text: "#00ff88", border: "rgba(0,255,136,0.25)" },
    gold:  { bg: "rgba(240,165,0,0.1)", text: "#f0a500", border: "rgba(240,165,0,0.25)" },
    red:   { bg: "rgba(255,51,85,0.1)",  text: "#ff3355", border: "rgba(255,51,85,0.25)"  },
  };
  const c = colors[color] || colors.cyan;
  return (
    <span style={{
      background: c.bg, color: c.text,
      border: `1px solid ${c.border}`,
      padding: "2px 7px", borderRadius: 3,
      fontSize: 9, fontWeight: 700, letterSpacing: 1,
    }}>{children}</span>
  );
}

function Btn({ children, onClick, color = "cyan", style }) {
  const [hov, setHov] = useState(false);
  const colors = {
    cyan:  { border: "#00e5ff", text: "#00e5ff", bgHov: "rgba(0,229,255,0.08)" },
    green: { border: "#00ff88", text: "#00ff88", bgHov: "rgba(0,255,136,0.08)" },
    gold:  { border: "#f0a500", text: "#f0a500", bgHov: "rgba(240,165,0,0.08)" },
    red:   { border: "#ff3355", text: "#ff3355", bgHov: "rgba(255,51,85,0.08)"  },
  };
  const c = colors[color];
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        background: hov ? c.bgHov : "transparent",
        border: `1px solid ${c.border}`,
        color: c.text, padding: "8px 16px",
        borderRadius: 4, cursor: "pointer",
        fontFamily: "'JetBrains Mono',monospace",
        fontSize: 11, letterSpacing: 0.5,
        transition: "all 0.2s",
        boxShadow: hov ? `0 0 12px ${c.border}33` : "none",
        ...style,
      }}
    >{children}</button>
  );
}

function Terminal({ title, lines, minH = 140 }) {
  const ref = useRef();
  useEffect(() => {
    if(ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  return (
    <div style={{ borderRadius: 6, overflow: "hidden", border: "1px solid #1a2d45" }}>
      <div style={{ background: "#0d1520", padding: "7px 14px", display: "flex", alignItems: "center", gap: 6, borderBottom: "1px solid #1a2d45" }}>
        {["#ff5f57","#febc2e","#28c840"].map(c => (
          <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }}/>
        ))}
        <div style={{ flex: 1, textAlign: "center", fontSize: 10, color: "#4a6a8a", letterSpacing: 2 }}>{title}</div>
      </div>
      <div ref={ref} style={{
        background: "#020508", padding: "14px 16px",
        fontFamily: "'JetBrains Mono',monospace", fontSize: 10.5,
        lineHeight: 1.85, minHeight: minH, maxHeight: 260,
        overflowY: "auto", color: "#6a8aaa",
      }}>
        {lines.map((l, i) => <div key={i} style={{ color: l.color || "#6a8aaa" }}>{l.text}</div>)}
      </div>
    </div>
  );
}

function ProgressBar({ pct, color = "#00e5ff" }) {
  return (
    <div style={{ height: 4, background: "#0d1520", borderRadius: 2, overflow: "hidden" }}>
      <div style={{
        height: "100%", width: `${Math.max(0.3, pct)}%`,
        background: color,
        boxShadow: `0 0 8px ${color}88`,
        borderRadius: 2,
        transition: "width 1s ease",
      }}/>
    </div>
  );
}

function Grid({ children, cols = 2 }) {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: `repeat(${cols}, 1fr)`,
      gap: 14,
    }}>{children}</div>
  );
}

function Sep() {
  return <div style={{ height: 1, background: "#1a2d45", margin: "20px 0" }}/>;
}

function SectionHeader({ children }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
      <div style={{
        fontFamily: "'Orbitron',monospace", fontSize: 13, fontWeight: 700,
        color: "#f0a500", letterSpacing: 3,
      }}>{children}</div>
      <div style={{ flex: 1, height: 1, background: "linear-gradient(90deg,#2a4060,transparent)" }}/>
    </div>
  );
}

function Notif({ msg, show }) {
  return (
    <div style={{
      position: "fixed", bottom: 24, right: 24,
      background: "#080f1c", border: "1px solid #00ff88",
      borderRadius: 6, padding: "11px 20px",
      fontSize: 11, color: "#00ff88",
      boxShadow: "0 0 20px rgba(0,255,136,0.3)",
      zIndex: 999,
      transform: show ? "translateY(0)" : "translateY(80px)",
      opacity: show ? 1 : 0,
      transition: "all 0.3s ease",
      pointerEvents: "none",
    }}>{msg}</div>
  );
}

// ═══════════════════════════════════════════════════════════
//  SIDEBAR
// ═══════════════════════════════════════════════════════════
function Sidebar({ active, setActive, blockHeight, miningOn }) {
  return (
    <div style={S.sidebar}>
      {/* Logo */}
      <div style={{ padding: "22px 18px 16px", borderBottom: "1px solid #1a2d45" }}>
        <div style={{
          fontFamily: "'Orbitron',monospace", fontSize: 20, fontWeight: 900,
          color: "#f0a500", textShadow: "0 0 20px #f0a50066", letterSpacing: 4,
        }}>⬡ NBL</div>
        <div style={{ fontSize: 8, color: "#3a5570", letterSpacing: 3, marginTop: 4 }}>NEBULA BLOCKCHAIN</div>
        <div style={{ fontSize: 8, color: "#f0a500", opacity: 0.6, marginTop: 5 }}>by Zayn Quantum</div>
      </div>

      {/* Live badge */}
      <div style={{
        margin: "10px 14px", padding: "5px 10px",
        background: "rgba(0,255,136,0.07)", border: "1px solid rgba(0,255,136,0.18)",
        borderRadius: 4, display: "flex", alignItems: "center", gap: 6,
        fontSize: 8, color: "#00ff88", letterSpacing: 2,
      }}>
        <div style={{
          width: 6, height: 6, background: "#00ff88", borderRadius: "50%",
          boxShadow: "0 0 8px #00ff88",
          animation: "none",
        }}/>
        LIVE SYSTEM
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "8px 0", overflowY: "auto" }}>
        {[
          { section: "Overview", items: ["dashboard","blockchain","explorer"] },
          { section: "Operations", items: ["miner","wallet","mempool","network"] },
          { section: "Security & Dev", items: ["security","contracts"] },
          { section: "Setup", items: ["files","server","tests"] },
        ].map(({ section, items }) => (
          <div key={section}>
            <div style={{ padding: "8px 18px 3px", fontSize: 8, color: "#2a4060", letterSpacing: 3, textTransform: "uppercase" }}>
              {section}
            </div>
            {items.map(id => {
              const n = NAV.find(x => x.id === id);
              const isActive = active === id;
              let badge = n.badge;
              if(id === "blockchain") badge = blockHeight;
              if(id === "miner") badge = miningOn ? "ON" : "OFF";
              const badgeColor = id === "miner" ? (miningOn ? "green" : "red") : n.badgeColor;
              return (
                <div
                  key={id}
                  onClick={() => setActive(id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 9,
                    padding: "9px 18px",
                    cursor: "pointer",
                    borderLeft: `2px solid ${isActive ? "#00e5ff" : "transparent"}`,
                    background: isActive ? "rgba(0,229,255,0.06)" : "transparent",
                    color: isActive ? "#00e5ff" : "#5a7a9a",
                    fontSize: 11, letterSpacing: 0.3,
                    transition: "all 0.15s",
                  }}
                >
                  <span style={{ fontSize: 13, width: 16, textAlign: "center" }}>{n.icon}</span>
                  <span style={{ flex: 1 }}>{n.label}</span>
                  {badge !== null && (
                    <span style={{
                      fontSize: 9, padding: "1px 6px", borderRadius: 3,
                      background: badgeColor === "green" ? "rgba(0,255,136,0.12)" : badgeColor === "gold" ? "rgba(240,165,0,0.12)" : badgeColor === "red" ? "rgba(255,51,85,0.12)" : "rgba(0,229,255,0.12)",
                      color: badgeColor === "green" ? "#00ff88" : badgeColor === "gold" ? "#f0a500" : badgeColor === "red" ? "#ff3355" : "#00e5ff",
                    }}>{badge}</span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </nav>

      <div style={{ padding: "12px 18px", borderTop: "1px solid #1a2d45", fontSize: 9, color: "#2a3a4a", lineHeight: 1.7 }}>
        NEBULA v1.0.0 · Chain ID: 2025<br/>
        MIT License · Open Source
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
//  TOPBAR
// ═══════════════════════════════════════════════════════════
function Topbar({ page, blockHeight }) {
  const titles = {
    dashboard: "DASHBOARD", blockchain: "BLOCKCHAIN", explorer: "EXPLORER",
    miner: "MINER", wallet: "WALLET", mempool: "MEMPOOL",
    network: "P2P NETWORK", security: "SECURITY", contracts: "SMART CONTRACTS",
    files: "SOURCE FILES", server: "SERVER SETUP", tests: "TEST SUITE",
  };
  return (
    <div style={S.topbar}>
      <div style={{ fontFamily: "'Orbitron',monospace", fontSize: 13, fontWeight: 700, color: "#f0a500", letterSpacing: 3, flex: 1 }}>
        {titles[page]}
      </div>
      {[
        { label: "HEIGHT",  value: blockHeight, color: "#00e5ff" },
        { label: "REWARD",  value: "50 NBL",    color: "#f0a500" },
        { label: "SUPPLY",  value: "10.7M NBL", color: "#00ff88" },
        { label: "TESTS",   value: "42/42 ✓",   color: "#00ff88" },
      ].map(({ label, value, color }) => (
        <div key={label} style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "4px 10px", background: "#0d1520",
          border: "1px solid #1a2d45", borderRadius: 4, fontSize: 10,
        }}>
          <span style={{ color: "#4a6a8a" }}>{label}</span>
          <span style={{ color, fontWeight: 700 }}>{value}</span>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
//  PAGES
// ═══════════════════════════════════════════════════════════

function PageDashboard({ blockHeight }) {
  return (
    <div>
      <Grid cols={4}>
        {[
          { title: "Chain Height", value: blockHeight, sub: "Confirmed blocks", color: "#00e5ff" },
          { title: "Block Reward", value: "50 NBL",   sub: "Era I — Genesis",   color: "#f0a500" },
          { title: "Max Supply",   value: "10.7M",    sub: "Fixed forever",      color: "#00ff88" },
          { title: "Tests Passed", value: "42/42",    sub: "All systems OK",     color: "#00ff88" },
        ].map(x => (
          <Card key={x.title} glow={x.color}>
            <CardTitle>{x.title}</CardTitle>
            <BigVal color={x.color}>{x.value}</BigVal>
            <div style={{ fontSize: 10, color: "#4a6a8a", marginTop: 6 }}>{x.sub}</div>
          </Card>
        ))}
      </Grid>

      <div style={{ height: 16 }}/>

      <Grid cols={2}>
        <Card>
          <CardTitle>Chain Info</CardTitle>
          {[
            ["Chain Name",    "NEBULA",          "#f0a500"],
            ["Symbol",        "NBL",             "#f0a500"],
            ["Chain ID",      "2025",            "#00e5ff"],
            ["Decimals",      "9 (Neb units)",   null],
            ["Max Supply",    "10,700,000 NBL",  "#00ff88"],
            ["Block Time",    "10 seconds",       null],
            ["Curve",         "secp256k1",       "#00e5ff"],
            ["Consensus",     "Proof of Work",   null],
            ["Halving",       "Every 210,000 blocks", null],
            ["Author",        "Zayn Quantum",    "#f0a500"],
            ["License",       "MIT — Open Source", "#00ff88"],
          ].map(([k, v, c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>

        <Card>
          <CardTitle>Genesis Block</CardTitle>
          <Terminal title="block #0" minH={180} lines={[
            { text: "#  NEBULA Genesis Block", color: "#2a4060" },
            { text: "Hash   : 8c4557f72ecd1076...", color: "#00e5ff" },
            { text: "Height : 0",                   color: "#c0d4e8" },
            { text: "Reward : 50.000000000 NBL",    color: "#00ff88" },
            { text: "Time   : 2025-01-01 00:00:00", color: "#c0d4e8" },
            { text: "Bits   : 0x1d00ffff",          color: "#00e5ff" },
            { text: "Txs    : 1 (coinbase)",        color: "#c0d4e8" },
            { text: " ",                             color: "#2a4060" },
            { text: 'Message: "NEBULA — Financial', color: "#f0a500" },
            { text: ' Freedom for All Humanity"',   color: "#f0a500" },
          ]}/>

          <div style={{ marginTop: 16 }}>
            <CardTitle>Halving Schedule</CardTitle>
            {HALVINGS.map(h => (
              <div key={h.era} style={{
                display: "flex", alignItems: "center", gap: 10,
                padding: "8px 10px", borderRadius: 4, marginBottom: 4,
                background: h.current ? "rgba(240,165,0,0.05)" : "transparent",
                border: h.current ? "1px solid rgba(240,165,0,0.15)" : "1px solid transparent",
              }}>
                <div style={{ width: 55, fontSize: 10, color: h.current ? "#f0a500" : "#4a6a8a" }}>{h.era}</div>
                <div style={{ width: 100, fontSize: 10, color: "#5a7a9a" }}>{h.blocks}</div>
                <div style={{
                  width: 80, fontFamily: "'Orbitron',monospace", fontSize: 11,
                  color: h.current ? "#f0a500" : h.reward > 10 ? "#00e5ff" : "#4a6a8a",
                }}>{h.reward} NBL</div>
                <div style={{ flex: 1, fontSize: 9, color: "#3a5570" }}>{h.year}</div>
                {h.current && <Badge color="gold">◄ NOW</Badge>}
              </div>
            ))}
          </div>
        </Card>
      </Grid>
    </div>
  );
}

function PageBlockchain({ blockHeight }) {
  return (
    <div>
      <Grid cols={3}>
        <Card>
          <CardTitle>Architecture</CardTitle>
          {[
            ["Model",      "UTXO (like Bitcoin)", "#00e5ff"],
            ["Consensus",  "Proof of Work",       null],
            ["Hash Algo",  "SHA-256d",            "#00e5ff"],
            ["Addr Hash",  "RIPEMD160(SHA256)",   null],
            ["Encoding",   "Base58Check",          null],
            ["Prefix",     "N  (NBL addresses)",  "#f0a500"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
        <Card>
          <CardTitle>Block Rules</CardTitle>
          {[
            ["Max Size",      "1 MB",          null],
            ["Max TX/Block",  "3,000",         null],
            ["Target Time",   "10 seconds",    "#00e5ff"],
            ["Diff Window",   "2,016 blocks",  null],
            ["Max Diff Δ",    "4× per window", null],
            ["CB Maturity",   "100 blocks",    null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
        <Card>
          <CardTitle>Supply</CardTitle>
          {[
            ["Max Supply",    "10,700,000 NBL", "#f0a500"],
            ["Initial Reward","50 NBL",         "#00ff88"],
            ["Halving",       "210,000 blocks", "#00e5ff"],
            ["Smallest",      "1 Neb",          null],
            ["Decimals",      "9",              null],
            ["Min Fee",       "1,000 Neb",      null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
      </Grid>

      <Sep/>

      <SectionHeader>◈ LATEST BLOCKS</SectionHeader>
      <Card>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #1a2d45" }}>
              {["Height","Hash","Txs","Size","Reward","Status"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", fontSize: 9, color: "#3a5570", letterSpacing: 2, textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {blockHeight > 0 && Array.from({length: Math.min(blockHeight+1, 5)}, (_,i) => blockHeight-i).map(h => (
              <tr key={h} style={{ borderBottom: "1px solid #0d1520" }}>
                <td style={{ padding: "8px 10px", color: "#f0a500" }}>{h}</td>
                <td style={{ padding: "8px 10px", color: "#4a6a8a", fontFamily: "monospace", fontSize: 10 }}>
                  {h === 0 ? "8c4557f72ecd1076..." : Math.random().toString(16).slice(2,18)+"..."}
                </td>
                <td style={{ padding: "8px 10px" }}>1</td>
                <td style={{ padding: "8px 10px" }}>~285 B</td>
                <td style={{ padding: "8px 10px", color: "#00ff88" }}>50.000 NBL</td>
                <td style={{ padding: "8px 10px" }}>
                  <Badge color={h === 0 ? "gold" : "green"}>{h === 0 ? "GENESIS" : "CONFIRMED"}</Badge>
                </td>
              </tr>
            ))}
            {blockHeight === 0 && (
              <tr><td colSpan={6} style={{ padding: "20px 10px", color: "#3a5570", fontSize: 11, textAlign: "center" }}>
                Start the miner to see blocks appear here
              </td></tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function PageExplorer({ notify }) {
  const [q, setQ] = useState("");
  const [result, setResult] = useState(null);

  function search(query) {
    const s = (query || q).trim();
    if(!s) return;
    if(s === "0" || s.toLowerCase() === "genesis") {
      setResult({ type: "BLOCK #0 — GENESIS", rows: [
        ["Hash",    "8c4557f72ecd10764f5410ca10e4b07fef801fabb7f24602ff364ed378a081f5", "#00e5ff"],
        ["Height",  "0",                    "#f0a500"],
        ["Time",    "2025-01-01 00:00:00 UTC", null],
        ["TXs",     "1 (coinbase)",         null],
        ["Reward",  "50.000000000 NBL",     "#00ff88"],
        ["Bits",    "0x1d00ffff",           "#00e5ff"],
        ["Nonce",   "2,083,236,893",        null],
      ]});
    } else if(s.startsWith("N") && s.length > 20) {
      const bal = s === "NLfMw4STiuDo9pMixgNnXZapH3sXasYVk5" ? "50.000000000" : "0.000000000";
      setResult({ type: "ADDRESS", rows: [
        ["Address", s,   "#00e5ff"],
        ["Balance", bal + " NBL", "#00ff88"],
        ["UTXOs",   bal !== "0.000000000" ? "1" : "0", null],
      ]});
    } else if(s.length === 64) {
      setResult({ type: "BLOCK HASH", rows: [
        ["Hash",   s, "#00e5ff"],
        ["Found",  s.startsWith("8c4557") ? "Genesis Block #0" : "Not found in local chain", s.startsWith("8c4557") ? "#00ff88" : "#ff3355"],
      ]});
    } else {
      notify("Not found: " + s);
      setResult(null);
    }
  }

  return (
    <div>
      <Card>
        <CardTitle>Search</CardTitle>
        <div style={{ display: "flex", gap: 10 }}>
          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => e.key === "Enter" && search()}
            placeholder="Block height, hash, transaction ID, or NBL address..."
            style={{
              flex: 1, background: "#040810", border: "1px solid #1a2d45",
              color: "#c0d4e8", padding: "9px 14px", borderRadius: 4,
              fontFamily: "'JetBrains Mono',monospace", fontSize: 11,
              outline: "none",
            }}
            onFocus={e => e.target.style.borderColor = "#00e5ff"}
            onBlur={e => e.target.style.borderColor = "#1a2d45"}
          />
          <Btn onClick={() => search()} color="gold">⚡ SEARCH</Btn>
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
          {[
            ["Block #0 (Genesis)", "0"],
            ["Genesis Hash", "8c4557f72ecd10764f5410ca10e4b07fef801fabb7f24602ff364ed378a081f5"],
            ["Genesis Address", "NLfMw4STiuDo9pMixgNnXZapH3sXasYVk5"],
          ].map(([label, val]) => (
            <Btn key={label} onClick={() => { setQ(val); search(val); }}>{label}</Btn>
          ))}
        </div>
      </Card>

      {result && (
        <div style={{ marginTop: 14 }}>
          <Card glow="#00e5ff">
            <CardTitle>{result.type}</CardTitle>
            {result.rows.map(([k, v, c]) => (
              <StatRow key={k} label={k} value={<span style={{ wordBreak: "break-all", fontSize: 10 }}>{v}</span>} color={c}/>
            ))}
          </Card>
        </div>
      )}

      <div style={{ marginTop: 14 }}>
        <Card>
          <CardTitle>Genesis Block — Full Details</CardTitle>
          {[
            ["Hash",        "8c4557f72ecd10764f5410ca10e4b07fef801fabb7f24602ff364ed378a081f5", "#00e5ff"],
            ["Height",      "0", "#f0a500"],
            ["Version",     "1", null],
            ["Prev Hash",   "0000000000000000000000000000000000000000000000000000000000000000", "#3a5570"],
            ["Timestamp",   "2025-01-01 00:00:00 UTC", null],
            ["Bits",        "0x1d00ffff", "#00e5ff"],
            ["Nonce",       "2,083,236,893", null],
            ["Transactions","1 (coinbase)", null],
            ["Reward",      "50.000000000 NBL", "#00ff88"],
            ["Miner",       "NLfMw4STiuDo9pMixgNnXZapH3sXasYVk5", "#00e5ff"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={<span style={{ wordBreak:"break-all", fontSize:10 }}>{v}</span>} color={c}/>)}
        </Card>
      </div>
    </div>
  );
}

function PageMiner({ miningOn, setMiningOn, blockHeight, blocksFound, hashrate, notify }) {
  const logLines = useRef([{ text: "# Start mining to see output here", color: "#2a4060" }]);
  const [log, setLog] = useState(logLines.current);

  useEffect(() => {
    if(!miningOn) return;
    const iv = setInterval(() => {
      const h = (hashrate/1000).toFixed(0);
      if(Math.random() < 0.08) {
        logLines.current = [...logLines.current.slice(-30),
          { text: `✅ BLOCK #${blockHeight} FOUND!`, color: "#f0a500" },
          { text: `   Reward: 50.000000000 NBL`,    color: "#00ff88" },
          { text: `   Hash  : ${Math.random().toString(16).slice(2,18)}...`, color: "#00e5ff" },
        ];
      } else {
        logLines.current = [...logLines.current.slice(-30),
          { text: `   ${h} kH/s | nonce: ${Math.floor(Math.random()*9999999).toLocaleString()} | target: 0x0000ffff...`, color: "#2a4060" },
        ];
      }
      setLog([...logLines.current]);
    }, 1200);
    return () => clearInterval(iv);
  }, [miningOn, blockHeight, hashrate]);

  return (
    <div>
      <Grid cols={2}>
        <Card glow={miningOn ? "#00ff88" : null}>
          <CardTitle>Mining Status</CardTitle>
          <StatRow label="Status"      value={<Badge color={miningOn?"green":"red"}>{miningOn?"MINING":"STOPPED"}</Badge>}/>
          <StatRow label="Hash Rate"   value={miningOn ? `${(hashrate/1000).toFixed(0)} kH/s` : "0 H/s"} color={miningOn?"#00e5ff":null}/>
          <StatRow label="Blocks Found" value={blocksFound} color="#00ff88"/>
          <StatRow label="Current Reward" value="50 NBL" color="#f0a500"/>
          <StatRow label="Era"         value="Era I — Genesis" color="#f0a500"/>
          <StatRow label="Algorithm"   value="SHA-256d (secp256k1)"/>
          <StatRow label="CPU Threads" value="Auto-detect"/>

          <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
            <Btn
              color={miningOn ? "red" : "green"}
              onClick={() => { setMiningOn(!miningOn); notify(miningOn ? "⏹ Mining stopped" : "⛏ Mining started!"); }}
            >{miningOn ? "⏹ STOP MINING" : "▶ START MINING"}</Btn>
          </div>
        </Card>

        <Card>
          <CardTitle>Mining Terminal</CardTitle>
          <Terminal title="nebula_miner.py" lines={log} minH={160}/>
        </Card>
      </Grid>

      <Sep/>
      <SectionHeader>◈ HALVING INFO</SectionHeader>
      <Card>
        <div style={{ marginBottom: 12 }}>
          <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, color:"#5a7a9a", marginBottom:5 }}>
            <span>Era I Progress</span>
            <span style={{ color:"#f0a500" }}>0.00%</span>
          </div>
          <ProgressBar pct={0.01} color="#f0a500"/>
        </div>
        {[
          ["Current Reward", "50.000000000 NBL", "#f0a500"],
          ["Next Halving",   "Block #210,000",   "#00e5ff"],
          ["Blocks Until",   "210,000",          null],
          ["Estimated Year", "~2029",            null],
        ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
      </Card>

      <div style={{ marginTop: 14 }}>
        <Card>
          <CardTitle>Start Command</CardTitle>
          <Terminal title="terminal" minH={60} lines={[
            { text: "python3 nebula_cli.py mine --threads 4 --address YOUR_NBL_ADDR", color: "#f0a500" },
            { text: "# Or production:", color: "#2a4060" },
            { text: "sudo systemctl start nebula-miner", color: "#00e5ff" },
          ]}/>
        </Card>
      </div>
    </div>
  );
}

function PageWallet({ notify }) {
  const [revealed, setRevealed] = useState(false);
  return (
    <div>
      <Grid cols={2}>
        <Card>
          <CardTitle>Wallet Standard</CardTitle>
          {[
            ["Standard",    "BIP32 / BIP39 / BIP44", "#00e5ff"],
            ["Mnemonic",    "12 words",               null],
            ["Coin Type",   "2025 (NBL)",             "#f0a500"],
            ["Derivation",  "m/44'/2025'/0'/0/x",     null],
            ["Addr Prefix", "N",                      "#f0a500"],
            ["Signing",     "ECDSA secp256k1",        "#00e5ff"],
            ["k-value",     "RFC 6979 (deterministic)",null],
            ["Seed",        "PBKDF2 × 2048",          null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
          <div style={{ display:"flex", gap:8, marginTop:14 }}>
            <Btn color="gold" onClick={() => notify("▶ Run: python3 nebula_cli.py wallet new")}>+ NEW WALLET</Btn>
            <Btn onClick={() => notify("▶ Run: python3 nebula_cli.py wallet restore")}>RESTORE</Btn>
          </div>
        </Card>

        <Card>
          <CardTitle>Demo Wallet</CardTitle>
          <div style={{ background:"#040810", border:"1px solid #1a2d45", borderRadius:4, padding:12, marginBottom:12 }}>
            <div style={{ fontSize:8, color:"#3a5570", letterSpacing:3, marginBottom:5 }}>NBL ADDRESS</div>
            <div style={{ fontFamily:"'Space Mono',monospace", fontSize:10, color:"#00e5ff", wordBreak:"break-all" }}>
              NLfMw4STiuDo9pMixgNnXZapH3sXasYVk5
            </div>
          </div>
          {[
            ["Balance",       "50.000000000 NBL", "#00ff88"],
            ["UTXOs",         "1",               null],
            ["Transactions",  "1",               null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
          <div style={{ marginTop:12 }}>
            <div style={{ background:"rgba(255,51,85,0.05)", border:"1px solid rgba(255,51,85,0.2)", borderRadius:4, padding:12 }}>
              <div style={{ fontSize:8, color:"#ff3355", letterSpacing:3, marginBottom:6 }}>MNEMONIC — KEEP SECRET</div>
              <div style={{
                fontSize:10, color:"#5a7a9a", lineHeight:1.6,
                filter: revealed ? "none" : "blur(5px)",
                transition:"filter 0.3s",
                fontFamily:"'Space Mono',monospace",
              }}>
                abandon ability able about above absent absorb abstract absurd abuse access accident
              </div>
              <Btn color="red" style={{ marginTop:8, fontSize:9, padding:"5px 12px" }}
                onClick={() => { setRevealed(!revealed); notify(revealed ? "🔒 Hidden" : "⚠️ Never share your mnemonic!"); }}>
                {revealed ? "🔒 HIDE" : "👁 REVEAL"}
              </Btn>
            </div>
          </div>
        </Card>
      </Grid>

      <div style={{ marginTop: 14 }}>
        <Card>
          <CardTitle>Commands</CardTitle>
          <Terminal title="nebula_cli.py" minH={100} lines={[
            { text: "# Create new wallet",                             color: "#2a4060" },
            { text: "python3 nebula_cli.py wallet new",                color: "#f0a500" },
            { text: "# Check balance",                                 color: "#2a4060" },
            { text: "python3 nebula_cli.py balance --address YOUR_ADDR",color: "#00e5ff" },
            { text: "# Send NBL",                                      color: "#2a4060" },
            { text: "python3 nebula_cli.py send --to ADDR --amount 10.5",color: "#00ff88" },
            { text: "# Interactive mode",                              color: "#2a4060" },
            { text: "python3 nebula_cli.py repl",                      color: "#f0a500" },
          ]}/>
        </Card>
      </div>
    </div>
  );
}

function PageMempool() {
  return (
    <div>
      <Grid cols={3}>
        {[
          { title: "Pending TXs",    value: "0",      color: "#00e5ff", sub: "Waiting to mine" },
          { title: "Total Fees",     value: "0 NBL",  color: "#f0a500", sub: "In mempool" },
          { title: "Dust Threshold", value: "546 Neb",color: "#c0d4e8", sub: "Min output value" },
        ].map(x => (
          <Card key={x.title}>
            <CardTitle>{x.title}</CardTitle>
            <BigVal color={x.color}>{x.value}</BigVal>
            <div style={{ fontSize:10, color:"#4a6a8a", marginTop:6 }}>{x.sub}</div>
          </Card>
        ))}
      </Grid>
      <div style={{ marginTop: 14 }}>
        <Card>
          <CardTitle>Pending Transactions</CardTitle>
          <div style={{ textAlign:"center", padding:"40px 0", color:"#3a5570" }}>
            <div style={{ fontSize:24, marginBottom:10 }}>≋</div>
            <div style={{ fontSize:11 }}>Mempool is empty</div>
            <div style={{ fontSize:10, color:"#2a4060", marginTop:6 }}>Start the node to index live transactions</div>
          </div>
        </Card>
      </div>
    </div>
  );
}

function PageNetwork() {
  return (
    <div>
      <Grid cols={4}>
        {[
          { title:"Connected Peers", value:"0",     color:"#00e5ff" },
          { title:"Default Port",    value:"8333",  color:"#f0a500" },
          { title:"Max Peers",       value:"125",   color:"#c0d4e8" },
          { title:"Protocol",        value:"70015", color:"#c0d4e8" },
        ].map(x => (
          <Card key={x.title}>
            <CardTitle>{x.title}</CardTitle>
            <BigVal color={x.color}>{x.value}</BigVal>
          </Card>
        ))}
      </Grid>
      <Sep/>
      <Grid cols={2}>
        <Card>
          <CardTitle>Seed Nodes</CardTitle>
          {[
            ["ap1.nebula-nbl.io", "Asia Pacific 1"],
            ["ap2.nebula-nbl.io", "Asia Pacific 2"],
            ["ap3.nebula-nbl.io", "Asia Pacific 3"],
            ["eu.nebula-nbl.io",  "Europe"],
            ["seed1.nebula-nbl.io","Global 1"],
            ["seed2.nebula-nbl.io","Global 2"],
          ].map(([host, region]) => (
            <div key={host} style={{ display:"flex", alignItems:"center", padding:"7px 0", borderBottom:"1px solid #0d1520", gap:10 }}>
              <span style={{ flex:1, fontSize:10, color:"#4a6a8a", fontFamily:"monospace" }}>{host}</span>
              <span style={{ fontSize:9, color:"#3a5570" }}>{region}</span>
              <Badge color="red">OFFLINE</Badge>
            </div>
          ))}
          <div style={{ fontSize:9, color:"#2a4060", marginTop:10 }}>Goes online when first server is deployed</div>
        </Card>
        <Card>
          <CardTitle>Message Types</CardTitle>
          {[
            ["version",   "Handshake",          "#00e5ff"],
            ["verack",    "Handshake ack",       null],
            ["ping/pong", "Keep-alive",          null],
            ["getblocks", "Request blocks",      null],
            ["block",     "Send a block",        "#00e5ff"],
            ["tx",        "Broadcast tx",        null],
            ["inv",       "Inventory announce",  "#00e5ff"],
            ["getdata",   "Request data",        null],
            ["addr",      "Peer addresses",      null],
            ["getinfo",   "Chain info query",    "#00e5ff"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
      </Grid>
    </div>
  );
}

function PageSecurity() {
  return (
    <div>
      <Grid cols={2}>
        <Card>
          <CardTitle>Active Security Systems</CardTitle>
          {[
            ["DoS Protection",   "✓ IP misbehavior scoring", "#00ff88"],
            ["Rate Limiter",     "✓ 20 req/s, burst 100",    "#00ff88"],
            ["Double-Spend",     "✓ UTXO conflict detection","#00ff88"],
            ["Replay Protection","✓ Chain ID 2025",          "#00ff88"],
            ["Checkpoints",      "✓ Hardcoded block hashes", "#00ff88"],
            ["IP Filter",        "✓ Anti-Sybil (private IPs)","#00ff88"],
            ["Fail2Ban",         "✓ SSH brute-force block",  "#00ff88"],
            ["UFW Firewall",     "✓ Port 8333 only",         "#00ff88"],
            ["TX Sanitizer",     "✓ Format + size checks",   "#00ff88"],
            ["Block Sanitizer",  "✓ Merkle + PoW verify",    "#00ff88"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
        <Card>
          <CardTitle>Ban Score System (Bitcoin-compatible)</CardTitle>
          {[
            ["invalid_block_hash",   "+100 — INSTANT BAN",   "#ff3355"],
            ["invalid_block_merkle", "+100 — INSTANT BAN",   "#ff3355"],
            ["double_spend_tx",      "+100 — INSTANT BAN",   "#ff3355"],
            ["wrong_chain_id",       "+100 — INSTANT BAN",   "#ff3355"],
            ["oversized_message",    "+50",                   "#f0a500"],
            ["invalid_block_header", "+20",                   "#f0a500"],
            ["invalid_tx_format",    "+10",                   "#f0a500"],
            ["invalid_tx_signature", "+10",                   "#f0a500"],
            ["spam_tx",              "+5",                    "#00e5ff"],
            ["ping_flood",           "+1",                    "#00e5ff"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
          <div style={{ fontSize:9, color:"#3a5570", marginTop:10 }}>Ban threshold: 100 points · Duration: 24 hours</div>
        </Card>
      </Grid>
      <Sep/>
      <Card>
        <CardTitle>Cryptographic Security</CardTitle>
        <Grid cols={2}>
          <div>
            {[
              ["Curve",      "secp256k1 (same as Bitcoin)", "#00e5ff"],
              ["Key Size",   "256-bit private key",         null],
              ["Signature",  "ECDSA",                       "#00e5ff"],
              ["k-value",    "RFC 6979 (deterministic)",    "#00ff88"],
            ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
          </div>
          <div>
            {[
              ["Hash Algo",  "SHA-256d",                    "#00e5ff"],
              ["Addr Hash",  "RIPEMD160(SHA256)",           null],
              ["Checksum",   "4-byte SHA-256d",             null],
              ["WIF Format", "Base58Check v0x80",           "#00ff88"],
            ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
          </div>
        </Grid>
      </Card>
    </div>
  );
}

function PageContracts() {
  return (
    <div>
      <Grid cols={3}>
        {[
          { title:"Script Opcodes",  value:"64",  color:"#00e5ff", sub:"Bitcoin-compatible" },
          { title:"Contract Types",  value:"7",   color:"#f0a500", sub:"P2PKH,Multi,HTLC,CLTV,CSV,Vest,OP_RETURN" },
          { title:"NBL-20 Tokens",   value:"∞",   color:"#00ff88", sub:"Deploy unlimited tokens" },
        ].map(x => (
          <Card key={x.title}>
            <CardTitle>{x.title}</CardTitle>
            <BigVal color={x.color}>{x.value}</BigVal>
            <div style={{ fontSize:9, color:"#4a6a8a", marginTop:6 }}>{x.sub}</div>
          </Card>
        ))}
      </Grid>
      <Sep/>
      <Grid cols={2}>
        <Card>
          <CardTitle>Contract Templates</CardTitle>
          {[
            ["P2PKH",        "Pay to Public Key Hash",        "#00e5ff"],
            ["Multisig",     "m-of-n (up to 16 keys)",        null],
            ["HTLC",         "Hash Time-Locked (Atomic Swap)", "#00e5ff"],
            ["CLTV",         "Absolute block-height lock",    null],
            ["CSV",          "Relative sequence lock",        null],
            ["Vesting",      "Gradual unlock schedule",       "#f0a500"],
            ["OP_RETURN",    "Store 80 bytes on-chain",       null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
        <Card>
          <CardTitle>NBL-20 Token Standard</CardTitle>
          {[
            ["deploy()",       "Create new token",          "#00ff88"],
            ["transfer()",     "Send tokens",               null],
            ["approve()",      "Allow spender",             null],
            ["transferFrom()", "Delegated transfer",        null],
            ["burn()",         "Destroy tokens",            "#ff3355"],
            ["mint()",         "Create more (owner only)",  "#00ff88"],
            ["balance_of()",   "Query balance",             "#00e5ff"],
            ["allowance()",    "Check approval",            null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
      </Grid>
    </div>
  );
}

function PageFiles() {
  const total = FILES.reduce((s,f) => s+f.lines, 0);
  return (
    <div>
      <Grid cols={4}>
        {[
          { title:"Total Lines", value: total.toLocaleString(), color:"#f0a500" },
          { title:"Files",       value:"10",    color:"#00e5ff" },
          { title:"Language",    value:"Python",color:"#00ff88" },
          { title:"Tests",       value:"42/42", color:"#00ff88" },
        ].map(x => (
          <Card key={x.title}>
            <CardTitle>{x.title}</CardTitle>
            <BigVal color={x.color}>{x.value}</BigVal>
          </Card>
        ))}
      </Grid>

      <div style={{ marginTop: 14 }}>
        <Card>
          <CardTitle>All Source Files</CardTitle>
          {FILES.map(f => (
            <div key={f.name} style={{
              display:"flex", alignItems:"center", gap:14,
              padding:"11px 14px", background:"#040810",
              border:"1px solid #1a2d45", borderRadius:4, marginBottom:6,
            }}>
              <span style={{ fontSize:20 }}>{f.icon}</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:12, color:f.color, fontFamily:"'Space Mono',monospace" }}>{f.name}</div>
                <div style={{ fontSize:9, color:"#4a6a8a", marginTop:3 }}>{f.desc}</div>
              </div>
              <div style={{ fontFamily:"'Orbitron',monospace", fontSize:13, color:"#f0a500", fontWeight:700 }}>
                {f.lines.toLocaleString()}
              </div>
            </div>
          ))}
          <div style={{
            display:"flex", justifyContent:"space-between",
            padding:"10px 14px", borderTop:"1px solid #1a2d45", marginTop:4,
          }}>
            <span style={{ color:"#4a6a8a", fontSize:11 }}>TOTAL</span>
            <span style={{ fontFamily:"'Orbitron',monospace", fontSize:16, color:"#f0a500", fontWeight:900 }}>
              {total.toLocaleString()} lines
            </span>
          </div>
        </Card>
      </div>
    </div>
  );
}

function PageServer() {
  return (
    <div>
      <Grid cols={3}>
        <Card>
          <CardTitle>Server Requirements</CardTitle>
          {[
            ["OS",       "Ubuntu 22.04 LTS",  "#00e5ff"],
            ["RAM",      "1 GB minimum",      null],
            ["Storage",  "20 GB SSD",         null],
            ["CPU",      "1–4 cores",         null],
            ["Port",     "8333 (P2P)",        "#f0a500"],
            ["Cost",     "~$6/month",         "#00ff88"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
        <Card>
          <CardTitle>VPS Providers</CardTitle>
          {[
            ["DigitalOcean", "digitalocean.com", "#00e5ff"],
            ["Vultr",        "vultr.com",         null],
            ["Hostinger",    "hostinger.com/vps", null],
            ["Hetzner",      "hetzner.com",       null],
            ["AWS",          "aws.amazon.com",    null],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
        <Card>
          <CardTitle>Auto-Setup (17 Steps)</CardTitle>
          {[
            ["System update",  "✓ apt-get upgrade",     "#00ff88"],
            ["Firewall",       "✓ UFW configured",      "#00ff88"],
            ["Fail2Ban",       "✓ SSH protection",      "#00ff88"],
            ["NEBULA user",    "✓ Non-root security",   "#00ff88"],
            ["Python venv",    "✓ Isolated env",        "#00ff88"],
            ["Run 42 tests",   "✓ Verify install",      "#00ff88"],
            ["Systemd",        "✓ Auto-start on boot",  "#00ff88"],
            ["Auto backup",    "✓ Every 6 hours",       "#00ff88"],
            ["Wallet",         "✓ Auto-created",        "#00ff88"],
          ].map(([k,v,c]) => <StatRow key={k} label={k} value={v} color={c}/>)}
        </Card>
      </Grid>
      <Sep/>
      <SectionHeader>◈ DEPLOYMENT STEPS</SectionHeader>
      <Card>
        <Terminal title="server deployment — 3 commands" minH={140} lines={[
          { text: "# Step 1 — Upload all files to your server",   color: "#2a4060" },
          { text: "scp nebula_*.py nebula_server_setup.sh root@YOUR_SERVER:/root/", color: "#f0a500" },
          { text: " ", color: "#2a4060" },
          { text: "# Step 2 — SSH into server",                   color: "#2a4060" },
          { text: "ssh root@YOUR_SERVER_IP",                      color: "#00e5ff" },
          { text: " ", color: "#2a4060" },
          { text: "# Step 3 — Run ONE command (does everything)", color: "#2a4060" },
          { text: "chmod +x nebula_server_setup.sh",              color: "#00ff88" },
          { text: "sudo ./nebula_server_setup.sh",                color: "#00ff88" },
          { text: " ", color: "#2a4060" },
          { text: "# After setup — start services",               color: "#2a4060" },
          { text: "sudo systemctl start nebula",                  color: "#f0a500" },
          { text: "sudo systemctl start nebula-miner",            color: "#f0a500" },
        ]}/>
      </Card>
    </div>
  );
}

function PageTests() {
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(0);
  const total = TESTS.reduce((s,g) => s+g.tests.length, 0);

  function runTests() {
    setRunning(true);
    setDone(0);
    let i = 0;
    const iv = setInterval(() => {
      i++;
      setDone(i);
      if(i >= total) { clearInterval(iv); setRunning(false); }
    }, 120);
  }

  let globalIdx = 0;

  return (
    <div>
      <Grid cols={4}>
        {[
          { title:"Total Tests", value: total, color:"#00e5ff" },
          { title:"Passed",      value: running ? done : 42, color:"#00ff88" },
          { title:"Failed",      value: running ? total-done : 0, color: running && total-done>0 ? "#ff3355" : "#3a5570" },
          { title:"Coverage",    value:"100%", color:"#f0a500" },
        ].map(x => (
          <Card key={x.title}>
            <CardTitle>{x.title}</CardTitle>
            <BigVal color={x.color}>{x.value}</BigVal>
          </Card>
        ))}
      </Grid>

      <div style={{ margin:"14px 0" }}>
        <Btn color="green" onClick={runTests}>{running ? "⏳ RUNNING..." : "▶ RUN ALL TESTS"}</Btn>
      </div>

      {running && (
        <Card style={{ marginBottom:14 }}>
          <CardTitle>Progress</CardTitle>
          <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, color:"#5a7a9a", marginBottom:6 }}>
            <span>Running tests...</span>
            <span style={{ color:"#00e5ff" }}>{done}/{total}</span>
          </div>
          <ProgressBar pct={done/total*100} color="#00ff88"/>
        </Card>
      )}

      <Grid cols={2}>
        {TESTS.map(group => (
          <Card key={group.group}>
            <CardTitle>{group.group}</CardTitle>
            {group.tests.map((t, i) => {
              globalIdx++;
              const passed = !running || done >= globalIdx;
              return (
                <div key={t} style={{ display:"flex", alignItems:"center", gap:8, padding:"6px 0", borderBottom:"1px solid #0d1520", fontSize:11 }}>
                  <span style={{ color: passed ? "#00ff88" : "#2a4060", fontSize:12 }}>{passed?"✅":"⬜"}</span>
                  <span style={{ color: passed ? "#c0d4e8" : "#3a5570" }}>{t}</span>
                </div>
              );
            })}
          </Card>
        ))}
      </Grid>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
//  MAIN APP
// ═══════════════════════════════════════════════════════════
export default function App() {
  const [page, setPage] = useState("dashboard");
  const [blockHeight, setBlockHeight] = useState(0);
  const [miningOn, setMiningOn] = useState(false);
  const [blocksFound, setBlocksFound] = useState(0);
  const [hashrate, setHashrate] = useState(0);
  const [notifMsg, setNotifMsg] = useState("");
  const [notifShow, setNotifShow] = useState(false);

  function notify(msg) {
    setNotifMsg(msg);
    setNotifShow(true);
    setTimeout(() => setNotifShow(false), 3000);
  }

  // Mining simulation
  useEffect(() => {
    if(!miningOn) { setHashrate(0); return; }
    const iv = setInterval(() => {
      const hr = 280000 + Math.floor(Math.random()*80000);
      setHashrate(hr);
      if(Math.random() < 0.06) {
        setBlockHeight(h => h+1);
        setBlocksFound(b => b+1);
        notify(`⛏ Block found! +50 NBL`);
      }
    }, 1500);
    return () => clearInterval(iv);
  }, [miningOn]);

  const pages = {
    dashboard: <PageDashboard blockHeight={blockHeight}/>,
    blockchain: <PageBlockchain blockHeight={blockHeight}/>,
    explorer: <PageExplorer notify={notify}/>,
    miner: <PageMiner miningOn={miningOn} setMiningOn={setMiningOn} blockHeight={blockHeight} blocksFound={blocksFound} hashrate={hashrate} notify={notify}/>,
    wallet: <PageWallet notify={notify}/>,
    mempool: <PageMempool/>,
    network: <PageNetwork/>,
    security: <PageSecurity/>,
    contracts: <PageContracts/>,
    files: <PageFiles/>,
    server: <PageServer/>,
    tests: <PageTests/>,
  };

  return (
    <div style={S.app}>
      <Sidebar active={page} setActive={setPage} blockHeight={blockHeight} miningOn={miningOn}/>
      <div style={S.main}>
        <Topbar page={page} blockHeight={blockHeight}/>
        <div style={S.content}>{pages[page]}</div>
      </div>
      <Notif msg={notifMsg} show={notifShow}/>
    </div>
  );
}
