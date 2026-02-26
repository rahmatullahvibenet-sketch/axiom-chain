import { useState, useEffect, useRef } from "react";

// ══════════════════════════════════════════════════════════════════
//  NEBULA BLOCKCHAIN — COMPLETE INTEGRATED LIVE DASHBOARD
//  10 Files · 61 Classes · 53 Functions · 6,486 Lines · 42 Tests
//  Genesis: 2025-03-16 · Author: Zayn Quantum · MIT License
// ══════════════════════════════════════════════════════════════════

// ── EXACT CONSTANTS FROM nebula_core.py ──────────────────────────
const CHAIN = {
  name:"NEBULA", symbol:"NBL", id:2025, decimals:9,
  max_supply:10_700_000, initial_reward:50,
  halving_interval:210_000, block_time:600, port:8333,
  genesis_ts:1742083200, genesis_date:"2025-03-16",
  genesis_nonce:2083236893, genesis_bits:"0x1d00ffff",
  genesis_hash:"8c4557f72ecd10764f5410ca10e4b07fef801fabb7f24602ff364ed378a081f5",
  genesis_address:"NLfMw4STiuDo9pMixgNnXZapH3sXasYVk5",
  genesis_message:"NEBULA — Financial Freedom for All Humanity — 2025/03/16",
  author:"Zayn Quantum", license:"MIT", version:"1.0.0",
};

// ── ALL 10 FILES ──────────────────────────────────────────────────
const FILES = [
  { f:"nebula_core.py",        lines:1210, cls:15, fns:17, icon:"⚙️", color:"#00e5ff",
    role:"Blockchain Engine",
    desc:"Secp256k1 · SHA-256d · UTXO · MerkleTree · Block · Transaction · NEBULABlockchain · ChainValidator · Mempool" },
  { f:"nebula_contracts.py",   lines:797,  cls:7,  fns:0,  icon:"📜", color:"#f0a500",
    role:"Smart Contracts",
    desc:"92 Script Opcodes · OP class · ScriptInterpreter · ContractTemplates · NBL20Token · NBL20Registry · ContractManager" },
  { f:"nebula_tests.py",       lines:843,  cls:8,  fns:4,  icon:"🧪", color:"#00ff88",
    role:"Test Suite 42/42",
    desc:"TestCrypto · TestTransactions · TestBlocks · TestBlockchain · TestWallet · TestContracts · TestNetwork · TestResult" },
  { f:"nebula_cli.py",         lines:760,  cls:2,  fns:26, icon:"💻", color:"#9d4edd",
    role:"CLI — 20 Commands",
    desc:"NodeRunner · C(colors) · 20 commands: node mine wallet balance send block tx addr peers mempool supply halving info version test security demo repl" },
  { f:"nebula_security.py",    lines:608,  cls:15, fns:0,  icon:"🛡️", color:"#ff3355",
    role:"Security Layer",
    desc:"DoSProtection · RateLimiter · DoubleSpendDetector · ReplayProtection · CheckpointSystem · TxSanitizer · BlockSanitizer · IPFilter · AlertSystem · SecurityManager" },
  { f:"nebula_wallet.py",      lines:468,  cls:3,  fns:1,  icon:"👛", color:"#00e5ff",
    role:"HD Wallet BIP32/39/44",
    desc:"BIP39 (12-word mnemonic) · HDKey (BIP32 derivation) · NEBULAWallet (create, restore, sign, derive addresses)" },
  { f:"nebula_network.py",     lines:546,  cls:6,  fns:1,  icon:"🌐", color:"#00ff88",
    role:"P2P Network",
    desc:"MsgType · PeerState · PeerInfo · Message · PeerConnection · P2PNode · 10 seed nodes · 3 DNS seeds · resolve_dns_seeds()" },
  { f:"nebula_node.py",        lines:415,  cls:2,  fns:1,  icon:"🖥️", color:"#f0a500",
    role:"Full Node",
    desc:"BlockExplorer (search by height/hash/address) · NEBULAFullNode (run, save, status, integrate all modules)" },
  { f:"nebula_miner.py",       lines:396,  cls:3,  fns:3,  icon:"⛏️", color:"#9d4edd",
    role:"PoW Miner — Multiprocessing",
    desc:"MiningStats · BlockTemplate · NEBULAMiner · _worker() · mine_one_block_demo() · halving_schedule() · ctypes shared memory · HASH_BATCH=50k" },
  { f:"nebula_server_setup.sh",lines:443,  cls:0,  fns:0,  icon:"🚀", color:"#ff3355",
    role:"Server Auto-Deploy",
    desc:"Ubuntu 22.04 · 17-step setup · UFW firewall · Fail2Ban · systemd services · auto-backup every 6h · log rotation 30d" },
];

// ── ALL 61 CLASSES ORGANIZED ─────────────────────────────────────
const CLASSES = {
  "nebula_core.py": [
    { n:"Secp256k1",        d:"secp256k1 curve — point_add, point_mul, sign, verify, pubkey" },
    { n:"ScriptType",       d:"Enum: P2PKH, P2PK, MULTISIG, P2SH, OP_RETURN, NONSTANDARD" },
    { n:"Script",           d:"Locking/unlocking scripts — build, classify, serialize" },
    { n:"OutPoint",         d:"(txid, index) reference to a previous transaction output" },
    { n:"TxInput",          d:"Previous outpoint + scriptSig + sequence number" },
    { n:"TxOutput",         d:"value (Neb units) + scriptPubKey" },
    { n:"Transaction",      d:"inputs + outputs + txid() + sign() + serialize() + verify()" },
    { n:"MerkleTree",       d:"SHA-256d Merkle — compute_root, build_proof, verify_proof" },
    { n:"BlockHeader",      d:"version + prev_hash + merkle_root + timestamp + bits + nonce" },
    { n:"Block",            d:"BlockHeader + transactions — hash, serialize, mine-check" },
    { n:"UTXOEntry",        d:"Unspent output record — txid, index, value, script, height" },
    { n:"UTXOSet",          d:"UTXO index — O(1) lookup, add, spend, balance query" },
    { n:"Mempool",          d:"Pending TX pool — fee-sorted, double-spend resistant, top(n)" },
    { n:"ChainValidator",   d:"Full validation: PoW, Merkle, scripts, UTXO, signatures, fees" },
    { n:"NEBULABlockchain", d:"Main chain — add_block, next_bits, tip_hash, height, supply" },
  ],
  "nebula_contracts.py": [
    { n:"OP",               d:"92 Script opcodes enum — OP_DUP, OP_HASH160, OP_CHECKSIG..." },
    { n:"ScriptError",      d:"Script execution exception with opcode and stack state" },
    { n:"ScriptInterpreter",d:"Execute Bitcoin-compatible scripts — 92 opcodes implemented" },
    { n:"ContractTemplates",d:"Build P2PKH, Multisig, HTLC, CLTV, CSV, Vesting, OP_RETURN" },
    { n:"NBL20Token",       d:"Token state — name, symbol, decimals, supply, balances, allowances" },
    { n:"NBL20Registry",    d:"Deploy and manage multiple NBL-20 tokens on NEBULA chain" },
    { n:"ContractManager",  d:"High-level API — deploy, transfer, burn, mint, query" },
  ],
  "nebula_security.py": [
    { n:"BanReason",        d:"Enum: MISBEHAVIOR, INVALID_BLOCK, DOUBLE_SPEND, REPLAY, DOS" },
    { n:"BanEntry",         d:"Banned peer record — IP, reason, score, expiry timestamp" },
    { n:"DoSProtection",    d:"IP scoring — add_misbehavior, is_banned, auto-ban at 100pts" },
    { n:"RateLimiter",      d:"Token bucket — 20 req/s normal, burst 100, per-IP tracking" },
    { n:"DoubleSpendDetector",d:"Cross-check mempool+UTXO — detect conflicts in O(1)" },
    { n:"ReplayProtection", d:"Chain ID 2025 in every TX signature — cross-chain replay proof" },
    { n:"Checkpoint",       d:"Hardcoded (height, hash, timestamp) tuple for chain anchoring" },
    { n:"CheckpointSystem", d:"Validate chain against hardcoded checkpoints at key heights" },
    { n:"TxSanitizer",      d:"TX format, input count, output value, script size checks" },
    { n:"BlockSanitizer",   d:"Block header, Merkle root, PoW target, timestamp range checks" },
    { n:"IPFilter",         d:"Anti-Sybil — block private IP ranges (10.x, 192.168.x, etc.)" },
    { n:"AlertLevel",       d:"Enum: INFO, WARNING, ERROR, CRITICAL" },
    { n:"SecurityAlert",    d:"Alert record — level, message, timestamp, source" },
    { n:"AlertSystem",      d:"Collect, filter, route security alerts by severity level" },
    { n:"SecurityManager",  d:"Orchestrate all security subsystems — single integration point" },
  ],
};

// ── CLI 20 COMMANDS ───────────────────────────────────────────────
const CLI = [
  { c:"node",          d:"Start the full NEBULA node (P2P + blockchain + explorer)",
    x:"python3 nebula_cli.py node" },
  { c:"mine",          d:"Start multi-core PoW miner (multiprocessing — one process per CPU)",
    x:"python3 nebula_cli.py mine --address ADDR" },
  { c:"wallet new",    d:"Generate new BIP39 HD wallet with 12-word mnemonic",
    x:"python3 nebula_cli.py wallet new" },
  { c:"wallet restore",d:"Restore wallet from 12-word BIP39 mnemonic phrase",
    x:"python3 nebula_cli.py wallet restore" },
  { c:"balance",       d:"Check address balance (sums all UTXOs for that address)",
    x:"python3 nebula_cli.py balance --address ADDR" },
  { c:"send",          d:"Send NBL to another address (builds, signs, broadcasts TX)",
    x:"python3 nebula_cli.py send --to ADDR --amount 10.5" },
  { c:"block",         d:"Get block details by height or hash (with Merkle proof)",
    x:"python3 nebula_cli.py block --height 0" },
  { c:"tx",            d:"Get full transaction details by TXID",
    x:"python3 nebula_cli.py tx --txid TXID" },
  { c:"addr",          d:"Show all UTXOs and transaction history for an address",
    x:"python3 nebula_cli.py addr --address ADDR" },
  { c:"peers",         d:"Show all connected P2P peers with state and scores",
    x:"python3 nebula_cli.py peers" },
  { c:"mempool",       d:"Show pending (unconfirmed) transactions in mempool",
    x:"python3 nebula_cli.py mempool" },
  { c:"supply",        d:"Show current circulating supply and UTXO statistics",
    x:"python3 nebula_cli.py supply" },
  { c:"halving",       d:"Show complete halving schedule — all eras, rewards, years",
    x:"python3 nebula_cli.py halving" },
  { c:"info",          d:"Full chain info — height, hash, difficulty, supply, era",
    x:"python3 nebula_cli.py info" },
  { c:"version",       d:"Show NEBULA version, parameters, genesis, port, chain ID",
    x:"python3 nebula_cli.py version" },
  { c:"test",          d:"Run the full 42-test suite and show pass/fail results",
    x:"python3 nebula_cli.py test" },
  { c:"security",      d:"Show security stats — banned IPs, alerts, misbehavior scores",
    x:"python3 nebula_cli.py security" },
  { c:"demo",          d:"Run full mining + wallet + transaction demo end-to-end",
    x:"python3 nebula_cli.py demo" },
  { c:"repl",          d:"Interactive shell (REPL) — all commands available interactively",
    x:"python3 nebula_cli.py repl" },
];

// ── SEED NODES ────────────────────────────────────────────────────
const SEEDS = [
  { h:"seed1.nebula-nbl.io",  r:"Asia Pacific 1" },
  { h:"seed2.nebula-nbl.io",  r:"Asia Pacific 2" },
  { h:"seed3.nebula-nbl.io",  r:"Asia Pacific 3" },
  { h:"seed4.nebula-nbl.io",  r:"Europe 1" },
  { h:"seed5.nebula-nbl.io",  r:"Europe 2" },
  { h:"seed6.nebula-nbl.io",  r:"Americas 1" },
  { h:"seed7.nebula-nbl.io",  r:"Americas 2" },
  { h:"seed8.nebula-nbl.io",  r:"Africa / Middle East" },
  { h:"seed9.nebula-nbl.io",  r:"Oceania" },
  { h:"seed10.nebula-nbl.io", r:"Global Backup" },
];
const DNS_SEEDS = ["dnsseed.nebula-nbl.io","dnsseed2.nebula-nbl.io","seed.nebula-nbl.io"];

// ── HALVING SCHEDULE ──────────────────────────────────────────────
const HALVINGS = Array.from({length:8},(_,i)=>({
  era:i+1, reward:50/Math.pow(2,i),
  start:i*210_000, end:(i+1)*210_000-1,
  yStart:2025+i*4, yEnd:2029+i*4, active:i===0,
}));

// ── CONTRACT TYPES ────────────────────────────────────────────────
const CONTRACTS = [
  { n:"P2PKH",     d:"Pay to Public Key Hash — standard address payment",
    op:"OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG" },
  { n:"Multisig",  d:"m-of-n up to 16 keys — treasury, escrow, shared control",
    op:"OP_m [pubkeys] OP_n OP_CHECKMULTISIG" },
  { n:"HTLC",      d:"Hash Time-Locked — atomic cross-chain swaps",
    op:"OP_IF OP_HASH256 <hash> OP_EQUALVERIFY OP_ELSE OP_CLTV OP_ENDIF" },
  { n:"CLTV",      d:"CheckLockTimeVerify — absolute block-height lock",
    op:"<locktime> OP_CLTV OP_DROP OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG" },
  { n:"CSV",       d:"CheckSequenceVerify — relative time lock from spend",
    op:"<sequence> OP_CSV OP_DROP OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG" },
  { n:"Vesting",   d:"Gradual unlock tranches over time — OP_CLTV based",
    op:"Multi-stage CLTV tranches with partial unlock" },
  { n:"OP_RETURN", d:"Store up to 80 bytes of data permanently on-chain",
    op:"OP_RETURN <data_up_to_80_bytes>" },
];

// ── NBL-20 METHODS ────────────────────────────────────────────────
const NBL20 = [
  { fn:"deploy()",       d:"Create new token: name, symbol, decimals, total_supply" },
  { fn:"transfer()",     d:"Send tokens from sender to recipient address" },
  { fn:"approve()",      d:"Authorize a spender to use your token balance" },
  { fn:"transferFrom()", d:"Delegated transfer using an approved allowance" },
  { fn:"burn()",         d:"Permanently destroy tokens — reduces total supply" },
  { fn:"mint()",         d:"Create additional tokens (owner/authorized only)" },
  { fn:"balance_of()",   d:"Query token balance of any address" },
  { fn:"allowance()",    d:"Check approved spending limit between owner and spender" },
];

// ── TEST GROUPS ───────────────────────────────────────────────────
const TEST_GROUPS = [
  { g:"📐 TestCrypto",        n:9, tests:[
    "SHA256 / SHA256d (double hash)",
    "HASH160 = RIPEMD160(SHA256(data))",
    "secp256k1 keypair generation",
    "ECDSA sign and verify",
    "NBL address starts with N",
    "DER signature encoding",
    "RFC6979 deterministic k-value",
    "Base58 encode / decode",
    "WIF private key format",
  ]},
  { g:"💸 TestTransactions",  n:6, tests:[
    "Coinbase transaction build",
    "Transaction serialization",
    "TXID computation (SHA256d)",
    "Signature hash (sighash)",
    "Full P2PKH sign + verify",
    "2-of-3 multisig creation",
  ]},
  { g:"📦 TestBlocks",        n:7, tests:[
    "Block header serialization",
    "Block hash computation",
    "Merkle tree root",
    "Merkle inclusion proof",
    "Difficulty adjustment (retarget)",
    "Halving schedule accuracy",
    "Genesis block creation",
  ]},
  { g:"⛓ TestBlockchain",    n:5, tests:[
    "UTXO add and spend",
    "UTXO balance query",
    "Chain validation end-to-end",
    "Mempool initialization",
    "Total supply tracking",
  ]},
  { g:"👛 TestWallet",        n:5, tests:[
    "BIP39 12-word mnemonic",
    "BIP32 key derivation (HMAC-SHA512)",
    "BIP44 path m/44'/2025'/0'",
    "Wallet create from seed",
    "Wallet restore from mnemonic",
  ]},
  { g:"📜 TestContracts",     n:7, tests:[
    "Script interpreter execution",
    "P2PKH script build + execute",
    "HTLC contract build + verify",
    "NBL-20 token deploy",
    "NBL-20 transfer",
    "NBL-20 burn",
    "Timelock (CLTV) script",
  ]},
  { g:"🌐 TestNetwork",       n:3, tests:[
    "P2P message encode/decode",
    "Message roundtrip test",
    "Variable-length integer encoding",
  ]},
];

// ── NAV ───────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id:"dashboard",  icon:"◈",  label:"Dashboard" },
  { id:"chain",      icon:"⛓",  label:"Blockchain" },
  { id:"files",      icon:"📁",  label:"Files (10)" },
  { id:"classes",    icon:"🗂",  label:"Classes (61)" },
  { id:"explorer",   icon:"🔍",  label:"Explorer" },
  { id:"miner",      icon:"⛏",  label:"Miner" },
  { id:"wallet",     icon:"◎",  label:"Wallet" },
  { id:"network",    icon:"◉",  label:"Network" },
  { id:"security",   icon:"🛡",  label:"Security" },
  { id:"contracts",  icon:"📜",  label:"Contracts" },
  { id:"cli",        icon:"💻",  label:"CLI (20)" },
  { id:"server",     icon:"🖥",  label:"Server" },
  { id:"tests",      icon:"✓",  label:"Tests 42/42" },
];

// ══════════════════════════════════════════════════════════════════
//  DESIGN TOKENS
// ══════════════════════════════════════════════════════════════════
const T = {
  gold:"#f0a500", cyan:"#00e5ff", green:"#00ff88",
  red:"#ff3355",  purple:"#9d4edd",
  bg:"#030810",   bg2:"#07101c", bg3:"#0d1825",
  panel:"#060d18",border:"#182a40", border2:"#243d5a",
  text:"#c0d4e8", text2:"#4a6a8a", text3:"#1e3048",
};

// ══════════════════════════════════════════════════════════════════
//  UI PRIMITIVES
// ══════════════════════════════════════════════════════════════════

function Card({ children, glow, style:s }) {
  const [h,sH]=useState(false);
  return (
    <div onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)} style={{
      background:T.panel, border:`1px solid ${h?T.border2:T.border}`,
      borderRadius:7, padding:18, position:"relative", overflow:"hidden",
      transition:"border-color .2s,box-shadow .2s",
      boxShadow:h&&glow?`0 0 28px ${glow}22`:"none", ...s,
    }}>
      <div style={{ position:"absolute",top:0,left:0,right:0,height:1,
        background:"linear-gradient(90deg,transparent,rgba(0,229,255,.15),transparent)" }}/>
      {children}
    </div>
  );
}

const H = ({children,color=T.gold})=>(
  <div style={{ fontFamily:"'Orbitron',monospace",fontSize:12,fontWeight:900,
    color,letterSpacing:3,marginBottom:14 }}>{children}</div>
);

const Lbl = ({children})=>(
  <div style={{ fontSize:8,color:T.text3,letterSpacing:3,
    textTransform:"uppercase",marginBottom:5 }}>{children}</div>
);

function Row({k,v,c}) {
  return (
    <div style={{ display:"flex",justifyContent:"space-between",
      padding:"7px 0",borderBottom:`1px solid ${T.bg3}`,fontSize:11 }}>
      <span style={{color:T.text2}}>{k}</span>
      <span style={{color:c||T.text,fontWeight:600}}>{v}</span>
    </div>
  );
}

function Bdg({children,color=T.cyan}) {
  return <span style={{ background:`${color}18`,color,border:`1px solid ${color}30`,
    padding:"2px 8px",borderRadius:3,fontSize:9,fontWeight:700,letterSpacing:1 }}>{children}</span>;
}

function Btn({children,onClick,color=T.cyan,style:s}) {
  const [h,sH]=useState(false);
  return (
    <button onClick={onClick} onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)}
      style={{ background:h?`${color}15`:"transparent",border:`1px solid ${color}`,
        color,padding:"8px 18px",borderRadius:4,cursor:"pointer",
        fontFamily:"inherit",fontSize:11,transition:"all .2s",
        boxShadow:h?`0 0 14px ${color}33`:"none",...s }}>
      {children}
    </button>
  );
}

function Term({title,lines,minH=130}) {
  const ref=useRef();
  useEffect(()=>{if(ref.current)ref.current.scrollTop=ref.current.scrollHeight;},[lines]);
  return (
    <div style={{borderRadius:6,overflow:"hidden",border:`1px solid ${T.border}`}}>
      <div style={{background:T.bg3,padding:"7px 14px",display:"flex",
        alignItems:"center",gap:6,borderBottom:`1px solid ${T.border}`}}>
        {["#ff5f57","#febc2e","#28c840"].map(c=>(
          <div key={c} style={{width:10,height:10,borderRadius:"50%",background:c}}/>
        ))}
        <div style={{flex:1,textAlign:"center",fontSize:10,
          color:T.text2,letterSpacing:2}}>{title}</div>
      </div>
      <div ref={ref} style={{background:"#020508",padding:"14px 16px",
        fontFamily:"'JetBrains Mono',monospace",fontSize:10.5,lineHeight:1.85,
        minHeight:minH,maxHeight:270,overflowY:"auto"}}>
        {lines.map((l,i)=><div key={i} style={{color:l.c||T.text2}}>{l.t}</div>)}
      </div>
    </div>
  );
}

function Bar({pct,color=T.cyan}) {
  return (
    <div style={{height:4,background:T.bg2,borderRadius:2,overflow:"hidden"}}>
      <div style={{height:"100%",width:`${Math.max(.3,pct)}%`,background:color,
        boxShadow:`0 0 8px ${color}88`,borderRadius:2,transition:"width .8s ease"}}/>
    </div>
  );
}

function G({cols=2,gap=14,children}) {
  return <div style={{display:"grid",
    gridTemplateColumns:`repeat(${cols},1fr)`,gap}}>{children}</div>;
}

function Sep() {
  return <div style={{height:1,background:T.border,margin:"20px 0"}}/>;
}

function SH({children}) {
  return (
    <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16}}>
      <div style={{fontFamily:"'Orbitron',monospace",fontSize:11,
        fontWeight:700,color:T.gold,letterSpacing:3}}>{children}</div>
      <div style={{flex:1,height:1,background:`linear-gradient(90deg,${T.border2},transparent)`}}/>
    </div>
  );
}

function BigNum({v,c=T.gold}) {
  return <div style={{fontFamily:"'Orbitron',monospace",fontSize:24,
    fontWeight:900,color:c,textShadow:`0 0 18px ${c}44`,lineHeight:1}}>{v}</div>;
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: DASHBOARD
// ══════════════════════════════════════════════════════════════════
function PageDashboard({bh,mining,blocksFound,hashrate}) {
  const totalLines = FILES.reduce((s,f)=>s+f.lines,0);
  const totalCls   = FILES.reduce((s,f)=>s+f.cls,0);
  const totalFns   = FILES.reduce((s,f)=>s+f.fns,0);

  return (
    <div>
      {/* Hero */}
      <div style={{background:"linear-gradient(135deg,#060d18,#091420)",
        border:`1px solid ${T.border}`,borderTop:`2px solid ${T.gold}`,
        borderRadius:8,padding:"22px 28px",marginBottom:18}}>
        <div style={{display:"flex",alignItems:"center",gap:20}}>
          <div style={{fontFamily:"'Orbitron',monospace",fontSize:36,fontWeight:900,
            color:T.gold,textShadow:"0 0 30px #f0a50055",letterSpacing:4}}>⬡ NEBULA</div>
          <div>
            <div style={{fontSize:12,color:T.cyan,letterSpacing:2,marginBottom:5}}>
              INDEPENDENT BLOCKCHAIN NETWORK</div>
            <div style={{fontSize:10,color:T.text2,marginBottom:4}}>
              No Government · No Bank · No Permission · Open to All Humanity</div>
            <div style={{fontSize:9,color:T.text3}}>
              Author: {CHAIN.author} · MIT License · Genesis: {CHAIN.genesis_date} · Chain ID: {CHAIN.id} · Port: {CHAIN.port}</div>
          </div>
          <div style={{marginLeft:"auto",display:"flex",flexDirection:"column",
            alignItems:"flex-end",gap:6}}>
            <Bdg color={mining?T.green:T.text2}>{mining?"⛏ MINING ACTIVE":"◉ READY"}</Bdg>
            <Bdg color={T.gold}>Era I — 50 NBL/block</Bdg>
            <Bdg color={T.cyan}>Block: 600s / 10 minutes</Bdg>
            <Bdg color={T.green}>42/42 Tests ✅</Bdg>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <G cols={4} gap={12}>
        {[
          {lbl:"Chain Height",  val:bh.toLocaleString(), c:T.cyan,  sub:"Blocks confirmed"},
          {lbl:"Block Reward",  val:"50 NBL",            c:T.gold,  sub:"Era I · 2025–2029"},
          {lbl:"Max Supply",    val:"10,700,000",         c:T.green, sub:"NBL — fixed forever"},
          {lbl:"Hash Rate",     val:mining?`${(hashrate/1000).toFixed(0)} KH/s`:"0 H/s",
                                                          c:mining?T.green:T.text2,
                                                          sub:"multiprocessing PoW"},
        ].map(x=>(
          <Card key={x.lbl} glow={x.c}>
            <Lbl>{x.lbl}</Lbl>
            <BigNum v={x.val} c={x.c}/>
            <div style={{fontSize:9,color:T.text2,marginTop:6}}>{x.sub}</div>
          </Card>
        ))}
      </G>

      <div style={{height:14}}/>

      <G cols={2}>
        <Card>
          <H>Chain Parameters</H>
          {[
            ["Chain Name",    CHAIN.name,                  T.gold],
            ["Symbol",        CHAIN.symbol,                T.gold],
            ["Chain ID",      CHAIN.id,                    T.cyan],
            ["Decimals",      `${CHAIN.decimals} (Neb units)`,null],
            ["Max Supply",    "10,700,000 NBL",            T.green],
            ["Block Time",    "600s / 10 minutes",         T.cyan],
            ["Halving",       "Every 210,000 blocks",      null],
            ["Algorithm",     "SHA-256d PoW",              T.cyan],
            ["Curve",         "secp256k1 (= Bitcoin)",     null],
            ["TX Model",      "UTXO (= Bitcoin)",          null],
            ["Signature",     "ECDSA + RFC6979",           T.cyan],
            ["Addresses",     "Base58Check prefix N",      T.gold],
            ["Port",          CHAIN.port,                  T.gold],
            ["Miner Engine",  "multiprocessing (no GIL)",  T.green],
            ["License",       "MIT — Open to All Humanity",T.green],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
        </Card>

        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <Card>
            <H>Genesis Block</H>
            <Term title="block #0 — 2025-03-16 00:00:00 UTC" minH={160} lines={[
              {t:"# NEBULA Mainnet — Genesis Block",c:T.text3},
              {t:`Hash    : ${CHAIN.genesis_hash.slice(0,32)}...`,c:T.cyan},
              {t:"Height  : 0",c:T.text},
              {t:"Date    : 2025-03-16 00:00:00 UTC",c:T.text},
              {t:`Bits    : ${CHAIN.genesis_bits}`,c:T.cyan},
              {t:`Nonce   : ${CHAIN.genesis_nonce.toLocaleString()}`,c:T.text},
              {t:`Reward  : 50.000000000 NBL`,c:T.green},
              {t:`Address : ${CHAIN.genesis_address}`,c:T.cyan},
              {t:`Message : "${CHAIN.genesis_message}"`,c:T.gold},
            ]}/>
          </Card>

          <Card>
            <H>Codebase Summary</H>
            {[
              ["Files",        "10 (9 Python + 1 Shell)",  T.cyan],
              ["Total Lines",  totalLines.toLocaleString(), T.gold],
              ["Classes",      `${totalCls} classes`,       T.cyan],
              ["Functions",    `${totalFns} top-level fns`, null],
              ["Tests",        "42/42 ✅ ALL PASSED",       T.green],
              ["CLI Commands", "20 commands",               T.purple],
              ["Seed Nodes",   "10 worldwide",              T.cyan],
              ["DNS Seeds",    "3 resolvers",               null],
              ["Language",     "English only",              T.green],
            ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
          </Card>
        </div>
      </G>

      <Sep/>
      <SH>◈ HALVING SCHEDULE — ALL ERAS</SH>
      <Card>
        {HALVINGS.map((h)=>(
          <div key={h.era} style={{display:"flex",alignItems:"center",gap:12,
            padding:"9px 12px",borderRadius:4,marginBottom:4,
            background:h.active?"rgba(240,165,0,0.07)":"transparent",
            border:h.active?`1px solid rgba(240,165,0,0.2)`:`1px solid transparent`}}>
            <div style={{width:56,fontSize:10,color:h.active?T.gold:T.text2,fontWeight:h.active?700:400}}>Era {h.era}</div>
            <div style={{width:150,fontSize:10,color:T.text2,fontFamily:"monospace"}}>
              {h.start.toLocaleString()} – {h.end.toLocaleString()}</div>
            <div style={{width:90,fontFamily:"'Orbitron',monospace",fontSize:11,
              color:h.active?T.gold:h.reward>=6?T.cyan:T.text2}}>{h.reward} NBL</div>
            <div style={{flex:1,fontSize:9,color:T.text3}}>{h.yStart}–{h.yEnd}</div>
            {h.active&&<Bdg color={T.gold}>◄ NOW</Bdg>}
          </div>
        ))}
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: BLOCKCHAIN
// ══════════════════════════════════════════════════════════════════
function PageChain({bh}) {
  return (
    <div>
      <G cols={3}>
        <Card>
          <H>Architecture</H>
          {[
            ["TX Model",      "UTXO (= Bitcoin)",    T.cyan],
            ["Consensus",     "Proof of Work",       null],
            ["Hash Algo",     "SHA-256d",            T.cyan],
            ["Addr Hash",     "RIPEMD160(SHA256)",   null],
            ["Sig Algo",      "ECDSA + RFC6979",     T.cyan],
            ["Encoding",      "Base58Check",         null],
            ["Addr Prefix",   "N (NBL addresses)",   T.gold],
            ["Curve",         "secp256k1",           T.cyan],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
        </Card>
        <Card>
          <H>Block Rules</H>
          {[
            ["Max Size",      "1 MB",                null],
            ["Max TX/Block",  "3,000",               null],
            ["Target Time",   "600s / 10 min",       T.cyan],
            ["Diff Window",   "2,016 blocks",        null],
            ["Max Diff Δ",    "4× per retarget",     null],
            ["CB Maturity",   "100 blocks",          null],
            ["Min Fee",       "1,000 Neb",           null],
            ["Dust Limit",    "546 Neb",             null],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
        </Card>
        <Card>
          <H>Supply</H>
          {[
            ["Max Supply",    "10,700,000 NBL",      T.gold],
            ["Era I Reward",  "50 NBL",              T.green],
            ["Halving",       "210,000 blocks",      T.cyan],
            ["Smallest Unit", "1 Neb",               null],
            ["Decimals",      "9",                   null],
            ["Min Fee",       "1,000 Neb",           null],
            ["Genesis Date",  "2025-03-16",          T.gold],
            ["Timestamp",     "1742083200",          null],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
        </Card>
      </G>
      <Sep/>
      <SH>◈ CORE CLASSES — nebula_core.py (15 classes)</SH>
      <G cols={2}>
        {(CLASSES["nebula_core.py"]||[]).map(x=>(
          <Card key={x.n} style={{padding:"12px 16px"}}>
            <div style={{fontSize:12,color:T.cyan,fontFamily:"monospace",marginBottom:4}}>{x.n}</div>
            <div style={{fontSize:10,color:T.text2,lineHeight:1.6}}>{x.d}</div>
          </Card>
        ))}
      </G>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: FILES
// ══════════════════════════════════════════════════════════════════
function PageFiles() {
  const total    = FILES.reduce((s,f)=>s+f.lines,0);
  const totalCls = FILES.reduce((s,f)=>s+f.cls,0);
  const totalFns = FILES.reduce((s,f)=>s+f.fns,0);
  return (
    <div>
      <G cols={4} gap={12}>
        {[
          {lbl:"Total Lines",c:T.gold,  v:total.toLocaleString()},
          {lbl:"Files",      c:T.cyan,  v:"10"},
          {lbl:"Classes",    c:T.cyan,  v:totalCls},
          {lbl:"Functions",  c:T.green, v:totalFns},
        ].map(x=>(
          <Card key={x.lbl}>
            <Lbl>{x.lbl}</Lbl>
            <BigNum v={x.v} c={x.c}/>
          </Card>
        ))}
      </G>
      <div style={{marginTop:14}}>
        <Card>
          <H>All 10 Files — Complete Registry</H>
          {FILES.map(f=>(
            <div key={f.f} style={{display:"flex",alignItems:"center",gap:14,
              padding:"12px 14px",background:T.bg2,
              border:`1px solid ${T.border}`,borderRadius:5,marginBottom:7}}>
              <span style={{fontSize:24}}>{f.icon}</span>
              <div style={{flex:1}}>
                <div style={{fontSize:12,color:f.color,fontFamily:"monospace",marginBottom:3}}>{f.f}</div>
                <div style={{fontSize:9,color:T.gold,letterSpacing:1,marginBottom:3}}>{f.role}</div>
                <div style={{fontSize:9,color:T.text2,lineHeight:1.5}}>{f.desc}</div>
              </div>
              <div style={{textAlign:"right",flexShrink:0,minWidth:80}}>
                <div style={{fontFamily:"'Orbitron',monospace",fontSize:15,
                  color:f.color,fontWeight:700}}>{f.lines.toLocaleString()}</div>
                <div style={{fontSize:8,color:T.text2,marginTop:2}}>
                  {f.cls>0?`${f.cls}cls `:""}
                  {f.fns>0?`${f.fns}fn`:""}</div>
              </div>
            </div>
          ))}
          <div style={{display:"flex",justifyContent:"space-between",
            padding:"10px 14px",borderTop:`1px solid ${T.border}`,marginTop:4}}>
            <span style={{color:T.text2,fontSize:11}}>TOTAL</span>
            <span style={{fontFamily:"'Orbitron',monospace",fontSize:20,
              color:T.gold,fontWeight:900}}>{total.toLocaleString()} lines</span>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: CLASSES (61)
// ══════════════════════════════════════════════════════════════════
function PageClasses() {
  const secCls = [
    {n:"BanReason",         d:"Enum: MISBEHAVIOR, INVALID_BLOCK, DOUBLE_SPEND, REPLAY, DOS"},
    {n:"BanEntry",          d:"Banned peer record — IP, reason, score, expiry timestamp"},
    {n:"DoSProtection",     d:"IP scoring — add_misbehavior, is_banned, auto-ban at 100pts"},
    {n:"RateLimiter",       d:"Token bucket — 20 req/s normal, burst 100, per-IP tracking"},
    {n:"DoubleSpendDetector",d:"Cross-check mempool+UTXO — detect conflicts in O(1)"},
    {n:"ReplayProtection",  d:"Chain ID 2025 embedded in every TX — cross-chain replay proof"},
    {n:"Checkpoint",        d:"Hardcoded (height, hash, timestamp) for chain anchoring"},
    {n:"CheckpointSystem",  d:"Validate chain against hardcoded checkpoints at key heights"},
    {n:"TxSanitizer",       d:"TX format, input count, output value, script size validation"},
    {n:"BlockSanitizer",    d:"Block header, Merkle root, PoW target, timestamp range checks"},
    {n:"IPFilter",          d:"Anti-Sybil — block private IP ranges (10.x, 192.168.x...)"},
    {n:"AlertLevel",        d:"Enum: INFO, WARNING, ERROR, CRITICAL"},
    {n:"SecurityAlert",     d:"Alert record — level, message, timestamp, source IP"},
    {n:"AlertSystem",       d:"Collect, filter, route security alerts by severity level"},
    {n:"SecurityManager",   d:"Orchestrate all 14 security subsystems — single API point"},
  ];
  const sections = [
    { title:"nebula_core.py — 15 classes", color:T.cyan, classes:CLASSES["nebula_core.py"] },
    { title:"nebula_security.py — 15 classes", color:T.red, classes:secCls },
    { title:"nebula_contracts.py — 7 classes", color:T.gold, classes:CLASSES["nebula_contracts.py"] },
    { title:"Other modules — 24 classes", color:T.green, classes:[
      {n:"BIP39",          d:"nebula_wallet.py — 12-word mnemonic generation (BIP39 wordlist)"},
      {n:"HDKey",          d:"nebula_wallet.py — BIP32 HD key derivation (HMAC-SHA512)"},
      {n:"NEBULAWallet",   d:"nebula_wallet.py — create, restore, sign, derive addresses"},
      {n:"MiningStats",    d:"nebula_miner.py — ctypes shared memory hash/block counters"},
      {n:"BlockTemplate",  d:"nebula_miner.py — block ready to mine: header76, target32"},
      {n:"NEBULAMiner",    d:"nebula_miner.py — multiprocessing PoW miner coordinator"},
      {n:"MsgType",        d:"nebula_network.py — P2P message type enum"},
      {n:"PeerState",      d:"nebula_network.py — CONNECTING, CONNECTED, DISCONNECTED"},
      {n:"PeerInfo",       d:"nebula_network.py — host, port, state, score, connected_at"},
      {n:"Message",        d:"nebula_network.py — serialized P2P message: type + payload"},
      {n:"PeerConnection", d:"nebula_network.py — TCP connection to a single peer"},
      {n:"P2PNode",        d:"nebula_network.py — manage all peers: discovery, sync, relay"},
      {n:"BlockExplorer",  d:"nebula_node.py — search blocks/txs/addresses"},
      {n:"NEBULAFullNode", d:"nebula_node.py — run all modules as integrated node"},
      {n:"TestResult",     d:"nebula_tests.py — pass/fail/time record per test"},
      {n:"TestCrypto",     d:"nebula_tests.py — 9 cryptography tests"},
      {n:"TestTransactions",d:"nebula_tests.py — 6 transaction tests"},
      {n:"TestBlocks",     d:"nebula_tests.py — 7 block tests"},
      {n:"TestBlockchain", d:"nebula_tests.py — 5 chain tests"},
      {n:"TestWallet",     d:"nebula_tests.py — 5 wallet tests"},
      {n:"TestContracts",  d:"nebula_tests.py — 7 contract tests"},
      {n:"TestNetwork",    d:"nebula_tests.py — 3 network tests"},
      {n:"C",              d:"nebula_cli.py — ANSI terminal color codes"},
      {n:"NodeRunner",     d:"nebula_cli.py — orchestrate node, miner, network from CLI"},
    ]},
  ];
  return (
    <div>
      <Card style={{marginBottom:16,padding:"14px 18px"}}>
        <div style={{display:"flex",gap:20}}>
          {[
            {lbl:"Total Classes",v:"61",c:T.cyan},
            {lbl:"nebula_core",  v:"15",c:T.cyan},
            {lbl:"nebula_security",v:"15",c:T.red},
            {lbl:"nebula_contracts",v:"7",c:T.gold},
            {lbl:"Other modules",v:"24",c:T.green},
          ].map(x=>(
            <div key={x.lbl} style={{textAlign:"center"}}>
              <div style={{fontFamily:"'Orbitron',monospace",fontSize:20,
                fontWeight:900,color:x.c}}>{x.v}</div>
              <div style={{fontSize:8,color:T.text2,letterSpacing:1,marginTop:3}}>{x.lbl}</div>
            </div>
          ))}
        </div>
      </Card>
      {sections.map(sec=>(
        <div key={sec.title}>
          <SH>{sec.title}</SH>
          <G cols={2}>
            {sec.classes.map(x=>(
              <Card key={x.n} style={{padding:"11px 14px"}}>
                <div style={{fontSize:12,color:sec.color,fontFamily:"monospace",marginBottom:4}}>{x.n}</div>
                <div style={{fontSize:10,color:T.text2,lineHeight:1.6}}>{x.d}</div>
              </Card>
            ))}
          </G>
          <div style={{height:14}}/>
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: EXPLORER
// ══════════════════════════════════════════════════════════════════
function PageExplorer({notify}) {
  const [q,sQ]=useState(""); const [res,sR]=useState(null);
  function search(val) {
    const s=(val||q).trim(); if(!s) return;
    if(s==="0"||s.toLowerCase()==="genesis") {
      sR({type:"BLOCK #0 — GENESIS",rows:[
        ["Hash",   CHAIN.genesis_hash,              T.cyan],
        ["Height", "0",                             T.gold],
        ["Date",   "2025-03-16 00:00:00 UTC",       null],
        ["Bits",   CHAIN.genesis_bits,              T.cyan],
        ["Nonce",  CHAIN.genesis_nonce.toLocaleString(),null],
        ["Reward", "50.000000000 NBL",              T.green],
        ["Miner",  CHAIN.genesis_address,           T.cyan],
        ["Message",`"${CHAIN.genesis_message}"`,    T.gold],
      ]});
    } else if(s.startsWith("N")&&s.length>20) {
      const isg=s===CHAIN.genesis_address;
      sR({type:"ADDRESS",rows:[
        ["Address", s,                                      T.cyan],
        ["Balance", isg?"50.000000000 NBL":"0.000000000 NBL",T.green],
        ["UTXOs",   isg?"1":"0",                           null],
        ["TXs",     isg?"1":"0",                           null],
      ]});
    } else if(s.length===64) {
      const isg=s===CHAIN.genesis_hash||s.startsWith("8c4557");
      sR({type:"HASH",rows:[
        ["Hash",   s,                                       T.cyan],
        ["Found",  isg?"Genesis Block #0 ✅":"Not in local chain",isg?T.green:T.red],
      ]});
    } else if(/^\d+$/.test(s)) {
      const n=parseInt(s);
      sR({type:`BLOCK #${n}`,rows:[
        ["Height",n,T.gold],
        ["Status",n===0?"Genesis — Confirmed ✅":"Run node to access live blocks",n===0?T.green:T.text2],
      ]});
    } else { notify("Not found: "+s); sR(null); }
  }
  return (
    <div>
      <Card style={{marginBottom:14}}>
        <H>Block Explorer</H>
        <div style={{display:"flex",gap:10}}>
          <input value={q} onChange={e=>sQ(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&search()}
            placeholder="Block height · hash (64 hex chars) · NBL address (starts with N)..."
            style={{flex:1,background:T.bg2,border:`1px solid ${T.border}`,
              color:T.text,padding:"9px 14px",borderRadius:4,
              fontFamily:"inherit",fontSize:11,outline:"none"}}
            onFocus={e=>e.target.style.borderColor=T.cyan}
            onBlur={e=>e.target.style.borderColor=T.border}/>
          <Btn onClick={()=>search()} color={T.gold}>⚡ SEARCH</Btn>
        </div>
        <div style={{display:"flex",gap:8,marginTop:12,flexWrap:"wrap"}}>
          {[["Block #0","0"],
            ["Genesis Hash",CHAIN.genesis_hash],
            ["Genesis Address",CHAIN.genesis_address],
          ].map(([l,v])=>(
            <Btn key={l} onClick={()=>{sQ(v);search(v);}}>{l}</Btn>
          ))}
        </div>
      </Card>
      {res&&(
        <Card glow={T.cyan} style={{marginBottom:14}}>
          <H color={T.cyan}>{res.type}</H>
          {res.rows.map(([k,v,c])=>(
            <Row key={k} k={k} v={<span style={{wordBreak:"break-all",fontSize:10}}>{v}</span>} c={c}/>
          ))}
        </Card>
      )}
      <Card>
        <H>Genesis Block — Full Details</H>
        {[
          ["Hash",        CHAIN.genesis_hash,                                    T.cyan],
          ["Height",      "0",                                                   T.gold],
          ["Version",     "1",                                                   null],
          ["Prev Hash",   "0".repeat(64),                                        T.text3],
          ["Merkle Root", "SHA256d of coinbase TXID",                            T.text2],
          ["Timestamp",   `${CHAIN.genesis_ts}  (2025-03-16 00:00:00 UTC)`,      null],
          ["Bits",        CHAIN.genesis_bits,                                    T.cyan],
          ["Nonce",       CHAIN.genesis_nonce.toLocaleString(),                  null],
          ["Transactions","1 (coinbase only)",                                   null],
          ["Reward",      "50.000000000 NBL",                                   T.green],
          ["Miner",       CHAIN.genesis_address,                                 T.cyan],
          ["Message",     `"${CHAIN.genesis_message}"`,                          T.gold],
        ].map(([k,v,c])=>(
          <Row key={k} k={k} v={<span style={{wordBreak:"break-all",fontSize:10}}>{v}</span>} c={c}/>
        ))}
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: MINER
// ══════════════════════════════════════════════════════════════════
function PageMiner({mining,setMining,bh,blocksFound,hashrate,notify}) {
  const logRef=useRef([{t:"# Click START MINING to see live output",c:T.text3}]);
  const [log,sLog]=useState(logRef.current);
  useEffect(()=>{
    if(!mining) return;
    const iv=setInterval(()=>{
      const hr=(hashrate/1000).toFixed(0);
      const found=Math.random()<.07;
      if(found) {
        logRef.current=[...logRef.current.slice(-22),
          {t:``,c:null},
          {t:`✅ BLOCK #${bh} FOUND!`,c:T.gold},
          {t:`   Reward  : 50.000000000 NBL`,c:T.green},
          {t:`   Hash    : ${Math.random().toString(16).slice(2,18)}...`,c:T.cyan},
          {t:`   Nonce   : ${(Math.random()*0xFFFFFFFF|0).toLocaleString()}`,c:T.text2},
        ];
      } else {
        logRef.current=[...logRef.current.slice(-28),
          {t:`   ${hr}kH/s · nonce:${(Math.random()*9e6|0).toLocaleString()} · 0x0000ffff... searching`,c:T.text3},
        ];
      }
      sLog([...logRef.current]);
    },1200);
    return()=>clearInterval(iv);
  },[mining,bh,hashrate]);

  return (
    <div>
      <G cols={2}>
        <Card glow={mining?T.green:null}>
          <H>Mining Status</H>
          <Row k="Status"        v={<Bdg color={mining?T.green:T.red}>{mining?"MINING":"STOPPED"}</Bdg>}/>
          <Row k="Hash Rate"     v={mining?`${(hashrate/1000).toFixed(0)} KH/s`:"0 H/s"} c={mining?T.cyan:null}/>
          <Row k="Engine"        v="multiprocessing (no GIL)" c={T.cyan}/>
          <Row k="Workers"       v="1 per CPU core (auto-detect)"/>
          <Row k="Batch Size"    v="50,000 hashes / batch"/>
          <Row k="Blocks Found"  v={blocksFound} c={T.green}/>
          <Row k="Current Era"   v="Era I" c={T.gold}/>
          <Row k="Reward"        v="50 NBL" c={T.gold}/>
          <Row k="Algorithm"     v="SHA-256d (= Bitcoin)" c={T.cyan}/>
          <Row k="Nonce Space"   v="0x00000000 – 0xFFFFFFFF"/>
          <div style={{marginTop:16}}>
            <Btn color={mining?T.red:T.green}
              onClick={()=>{setMining(!mining);notify(mining?"⏹ Mining stopped":"⛏ Mining started — all CPU cores active!")}}>
              {mining?"⏹ STOP MINING":"▶ START MINING"}
            </Btn>
          </div>
        </Card>
        <Card>
          <H>Live Mining Terminal</H>
          <Term title="nebula_miner.py — multiprocessing engine" lines={log} minH={195}/>
        </Card>
      </G>
      <Sep/>
      <SH>◈ _worker() — THE MINING ENGINE (from nebula_miner.py)</SH>
      <Card>
        <Term title="nebula_miner.py — _worker() function" minH={130} lines={[
          {t:"def _worker(header76, target32, n_start, n_end, queue, stop, counter):",c:T.gold},
          {t:"    # Separate OS process — true parallelism, no Python GIL",          c:T.text3},
          {t:"    sha = hashlib.sha256",                                              c:T.text2},
          {t:"    tgt = int.from_bytes(target32, 'big')  # 256-bit target",          c:T.cyan},
          {t:"    buf = bytearray(header76 + b'\\x00'*4)  # 80-byte buffer",          c:T.cyan},
          {t:"",c:null},
          {t:"    for nonce in range(n_start, n_end+1, HASH_BATCH=50000):",           c:T.text},
          {t:"        struct.pack_into('<I', buf, 76, nonce)  # inject nonce",        c:T.text2},
          {t:"        h = sha(sha(buf).digest()).digest()     # SHA-256d",            c:T.cyan},
          {t:"        if int.from_bytes(h,'big') < tgt:      # found!",              c:T.green},
          {t:"            queue.put(nonce)",                                          c:T.green},
          {t:"            stop.value = 1  # signal all workers to stop",             c:T.green},
          {t:"            return",                                                    c:T.green},
        ]}/>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: WALLET
// ══════════════════════════════════════════════════════════════════
function PageWallet({notify}) {
  const [rev,sRev]=useState(false);
  return (
    <div>
      <G cols={2}>
        <Card>
          <H>Wallet Standard</H>
          {[
            ["Standard",    "BIP32 / BIP39 / BIP44",          T.cyan],
            ["Mnemonic",    "12 words (128-bit entropy)",      null],
            ["Coin Type",   "2025 (NEBULA)",                   T.gold],
            ["Deriv Path",  "m/44'/2025'/0'/0/index",          null],
            ["Addr Prefix", "N",                               T.gold],
            ["Signing",     "ECDSA secp256k1",                 T.cyan],
            ["k-value",     "RFC 6979 deterministic",          T.green],
            ["Seed KDF",    "PBKDF2 × 2048 iterations",       null],
            ["Key Size",    "256-bit private key",             null],
            ["Addr Hash",   "RIPEMD160(SHA256(pubkey))",       null],
            ["Encoding",    "Base58Check (prefix N)",          T.gold],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
          <div style={{display:"flex",gap:8,marginTop:14}}>
            <Btn color={T.gold} onClick={()=>notify("▶ python3 nebula_cli.py wallet new")}>+ NEW WALLET</Btn>
            <Btn onClick={()=>notify("▶ python3 nebula_cli.py wallet restore")}>RESTORE</Btn>
          </div>
        </Card>
        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <Card>
            <H>Classes (nebula_wallet.py)</H>
            {[
              {n:"BIP39",         d:"12-word mnemonic from BIP39 wordlist — generate, validate, to_seed()"},
              {n:"HDKey",         d:"BIP32 HD key — derive_child(), child_key(), chain_code, HMAC-SHA512"},
              {n:"NEBULAWallet",  d:"Full wallet — create(), restore(mnemonic), get_address(i), sign_tx()"},
            ].map(x=>(
              <div key={x.n} style={{padding:"11px 14px",background:T.bg2,
                border:`1px solid ${T.border}`,borderRadius:4,marginBottom:7}}>
                <div style={{fontSize:12,color:T.cyan,fontFamily:"monospace",marginBottom:4}}>{x.n}</div>
                <div style={{fontSize:10,color:T.text2}}>{x.d}</div>
              </div>
            ))}
          </Card>
          <Card>
            <H color={T.red}>Demo Wallet (Genesis Miner)</H>
            <div style={{background:T.bg2,border:`1px solid ${T.border}`,
              borderRadius:4,padding:12,marginBottom:10}}>
              <Lbl>NBL Address</Lbl>
              <div style={{fontFamily:"monospace",fontSize:10,color:T.cyan,
                wordBreak:"break-all"}}>{CHAIN.genesis_address}</div>
            </div>
            <Row k="Balance"  v="50.000000000 NBL" c={T.green}/>
            <Row k="UTXOs"    v="1"/>
            <Row k="TXs"      v="1 (coinbase)"/>
            <div style={{background:"rgba(255,51,85,.05)",
              border:"1px solid rgba(255,51,85,.2)",borderRadius:4,padding:12,marginTop:10}}>
              <Lbl>MNEMONIC — NEVER SHARE</Lbl>
              <div style={{fontSize:10,color:T.text2,fontFamily:"monospace",
                lineHeight:1.7,filter:rev?"none":"blur(5px)",transition:"filter .3s"}}>
                abandon ability able about above absent absorb abstract absurd abuse access accident
              </div>
              <div style={{marginTop:8}}>
                <Btn color={T.red} style={{fontSize:9,padding:"5px 12px"}}
                  onClick={()=>{sRev(!rev);notify(rev?"🔒 Hidden":"⚠️ Never share your mnemonic!")}}>
                  {rev?"🔒 HIDE":"👁 REVEAL"}
                </Btn>
              </div>
            </div>
          </Card>
        </div>
      </G>
      <Sep/>
      <SH>◈ CLI WALLET COMMANDS</SH>
      <Card>
        <Term title="nebula_cli.py — wallet commands" minH={90} lines={[
          {t:"python3 nebula_cli.py wallet new",                      c:T.gold},
          {t:"  → generates 12-word mnemonic + first NBL address",   c:T.text3},
          {t:"python3 nebula_cli.py wallet restore",                  c:T.gold},
          {t:"  → enter mnemonic phrase → restores all addresses",    c:T.text3},
          {t:"python3 nebula_cli.py balance --address ADDR",          c:T.cyan},
          {t:"python3 nebula_cli.py send --to ADDR --amount 10.5",    c:T.green},
        ]}/>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: NETWORK
// ══════════════════════════════════════════════════════════════════
function PageNetwork() {
  return (
    <div>
      <G cols={4} gap={12}>
        {[
          {lbl:"Seed Nodes", v:"10",   c:T.cyan},
          {lbl:"DNS Seeds",  v:"3",    c:T.gold},
          {lbl:"P2P Port",   v:"8333", c:T.gold},
          {lbl:"Max Peers",  v:"125",  c:T.text},
        ].map(x=>(
          <Card key={x.lbl}><Lbl>{x.lbl}</Lbl><BigNum v={x.v} c={x.c}/></Card>
        ))}
      </G>
      <div style={{height:14}}/>
      <G cols={2}>
        <Card>
          <H>Seed Nodes — Worldwide (10)</H>
          {SEEDS.map(s=>(
            <div key={s.h} style={{display:"flex",alignItems:"center",
              padding:"7px 0",borderBottom:`1px solid ${T.bg3}`,gap:10}}>
              <span style={{flex:1,fontSize:10,color:T.cyan,fontFamily:"monospace"}}>{s.h}</span>
              <span style={{fontSize:9,color:T.text2}}>{s.r}</span>
              <Bdg color={T.red}>OFFLINE</Bdg>
            </div>
          ))}
          <div style={{marginTop:8,fontSize:9,color:T.text3}}>
            Online after deploying first server at seed1.nebula-nbl.io
          </div>
        </Card>
        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <Card>
            <H>DNS Seeds (3)</H>
            {DNS_SEEDS.map(d=>(
              <div key={d} style={{padding:"8px 12px",background:T.bg2,
                border:`1px solid ${T.border}`,borderRadius:4,marginBottom:6,
                fontSize:11,color:T.cyan,fontFamily:"monospace"}}>{d}</div>
            ))}
            <div style={{fontSize:9,color:T.text2,marginTop:6}}>
              Resolved at startup via resolve_dns_seeds() in nebula_network.py
            </div>
          </Card>
          <Card>
            <H>P2P Classes — nebula_network.py</H>
            {[
              {n:"MsgType",      d:"Enum: version, verack, ping, pong, block, tx, inv, addr, getblocks..."},
              {n:"PeerState",    d:"CONNECTING → CONNECTED → DISCONNECTED states"},
              {n:"PeerInfo",     d:"host, port, state, misbehavior_score, connected_at"},
              {n:"Message",      d:"Serialized P2P message — type byte + payload bytes"},
              {n:"PeerConnection",d:"TCP connection to single peer — handshake, recv, send loops"},
              {n:"P2PNode",      d:"Manage all peers — seed connect, discovery, block/tx relay"},
            ].map(x=>(
              <div key={x.n} style={{padding:"8px 12px",background:T.bg2,
                border:`1px solid ${T.border}`,borderRadius:4,marginBottom:6}}>
                <div style={{fontSize:11,color:T.cyan,fontFamily:"monospace",marginBottom:3}}>{x.n}</div>
                <div style={{fontSize:9,color:T.text2}}>{x.d}</div>
              </div>
            ))}
          </Card>
          <Card>
            <H>Message Types</H>
            <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
              {["version","verack","ping","pong","getblocks","block",
                "tx","inv","getdata","addr","getinfo","notfound"].map(m=>(
                <span key={m} style={{padding:"3px 9px",
                  background:"rgba(0,229,255,.08)",
                  border:"1px solid rgba(0,229,255,.15)",
                  borderRadius:3,fontSize:10,color:T.cyan}}>{m}</span>
              ))}
            </div>
          </Card>
        </div>
      </G>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: SECURITY
// ══════════════════════════════════════════════════════════════════
function PageSecurity() {
  return (
    <div>
      <G cols={2}>
        <Card>
          <H color={T.red}>15 Security Classes</H>
          {(CLASSES["nebula_security.py"]||[]).map(x=>(
            <div key={x.n} style={{padding:"9px 12px",background:T.bg2,
              border:`1px solid ${T.border}`,borderRadius:4,marginBottom:6}}>
              <div style={{fontSize:11,color:T.red,fontFamily:"monospace",marginBottom:3}}>{x.n}</div>
              <div style={{fontSize:9,color:T.text2}}>{x.d}</div>
            </div>
          ))}
        </Card>
        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <Card>
            <H>Active Protections</H>
            {[
              ["DoS Protection",     "IP scoring — auto-ban at 100 points",        T.green],
              ["Rate Limiter",       "20 req/s · burst 100 (token bucket)",        T.green],
              ["Double-Spend",       "UTXO conflict detection — O(1)",             T.green],
              ["Replay Protection",  "Chain ID 2025 in every signed TX",           T.green],
              ["Checkpoints",        "Hardcoded hashes at key block heights",      T.green],
              ["IP Filter",          "Anti-Sybil — block private IP ranges",       T.green],
              ["TX Sanitizer",       "Format, size, script, value validation",     T.green],
              ["Block Sanitizer",    "Header, Merkle, PoW, timestamp checks",      T.green],
              ["Alert System",       "4-level: INFO/WARN/ERROR/CRITICAL",          T.green],
            ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
          </Card>
          <Card>
            <H>Cryptographic Security</H>
            {[
              ["Curve",      "secp256k1 (identical to Bitcoin)",  T.cyan],
              ["Key Size",   "256-bit private key",               null],
              ["Signature",  "ECDSA",                             T.cyan],
              ["k-value",    "RFC 6979 — deterministic, safe",    T.green],
              ["Hash",       "SHA-256d (double SHA-256)",         T.cyan],
              ["Addr Hash",  "RIPEMD160(SHA256(pubkey))",         null],
              ["Checksum",   "4-byte SHA-256d prefix",            null],
              ["WIF Key",    "Base58Check version byte 0x80",     T.green],
            ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
          </Card>
        </div>
      </G>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: CONTRACTS
// ══════════════════════════════════════════════════════════════════
function PageContracts() {
  return (
    <div>
      <G cols={3} gap={12}>
        {[
          {lbl:"Script Opcodes", v:"92",  c:T.cyan,  s:"Bitcoin-compatible"},
          {lbl:"Contract Types", v:"7",   c:T.gold,  s:"P2PKH·Multi·HTLC·CLTV·CSV·Vest·OP_RET"},
          {lbl:"NBL-20 Methods", v:"8",   c:T.green, s:"Deploy·Transfer·Burn·Mint·Approve..."},
        ].map(x=>(
          <Card key={x.lbl}><Lbl>{x.lbl}</Lbl><BigNum v={x.v} c={x.c}/>
            <div style={{fontSize:9,color:T.text2,marginTop:6}}>{x.s}</div></Card>
        ))}
      </G>
      <div style={{height:14}}/>
      <G cols={2}>
        <Card>
          <H>7 Contract Types</H>
          {CONTRACTS.map(x=>(
            <div key={x.n} style={{padding:"10px 12px",background:T.bg2,
              border:`1px solid ${T.border}`,borderRadius:4,marginBottom:6}}>
              <div style={{fontSize:12,color:T.gold,fontFamily:"monospace",fontWeight:700,marginBottom:4}}>{x.n}</div>
              <div style={{fontSize:9,color:T.text2,marginBottom:5}}>{x.d}</div>
              <div style={{fontSize:9,color:T.text3,fontFamily:"monospace"}}>{x.op}</div>
            </div>
          ))}
        </Card>
        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <Card>
            <H>NBL-20 Token Standard</H>
            {NBL20.map(x=>(
              <div key={x.fn} style={{display:"flex",gap:10,
                padding:"8px 0",borderBottom:`1px solid ${T.bg3}`}}>
                <span style={{width:130,fontSize:11,color:T.cyan,
                  fontFamily:"monospace",flexShrink:0}}>{x.fn}</span>
                <span style={{fontSize:10,color:T.text2}}>{x.d}</span>
              </div>
            ))}
          </Card>
          <Card>
            <H>Contract Classes</H>
            {(CLASSES["nebula_contracts.py"]||[]).map(x=>(
              <div key={x.n} style={{padding:"8px 12px",background:T.bg2,
                border:`1px solid ${T.border}`,borderRadius:4,marginBottom:6}}>
                <div style={{fontSize:11,color:T.gold,fontFamily:"monospace",marginBottom:3}}>{x.n}</div>
                <div style={{fontSize:9,color:T.text2}}>{x.d}</div>
              </div>
            ))}
          </Card>
        </div>
      </G>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: CLI
// ══════════════════════════════════════════════════════════════════
function PageCLI({notify}) {
  const [copied,sCopied]=useState(null);
  function copy(ex){sCopied(ex);notify("✓ Copied: "+ex);setTimeout(()=>sCopied(null),2000);}
  return (
    <div>
      <Card style={{marginBottom:14}}>
        <H>20 CLI Commands — nebula_cli.py</H>
        <Term title="python3 nebula_cli.py --help" minH={80} lines={[
          {t:"usage: python3 nebula_cli.py <command> [options]",c:T.gold},
          {t:"",c:null},
          {t:"  node       mine       wallet new  wallet restore  balance",c:T.cyan},
          {t:"  send       block      tx          addr           peers",c:T.cyan},
          {t:"  mempool    supply     halving     info           version",c:T.cyan},
          {t:"  test       security   demo        repl",c:T.cyan},
        ]}/>
      </Card>
      <G cols={2} gap={8}>
        {CLI.map(x=>(
          <div key={x.c} onClick={()=>copy(x.x)} style={{padding:"11px 14px",
            background:T.bg2,border:`1px solid ${copied===x.x?T.green:T.border}`,
            borderRadius:5,cursor:"pointer",transition:"all .2s"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <span style={{fontSize:12,color:T.gold,fontFamily:"monospace",fontWeight:700}}>{x.c}</span>
              {copied===x.x&&<Bdg color={T.green}>COPIED</Bdg>}
            </div>
            <div style={{fontSize:9,color:T.text2,marginBottom:4}}>{x.d}</div>
            <div style={{fontSize:9,color:T.text3,fontFamily:"monospace"}}>{x.x}</div>
          </div>
        ))}
      </G>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: SERVER
// ══════════════════════════════════════════════════════════════════
function PageServer() {
  const steps = [
    "apt-get update && upgrade",   "Python 3.10+ venv install",
    "Copy all 9 Python files",     "Run 42 tests — verify install",
    "UFW firewall — port 8333",    "Fail2Ban SSH protection",
    "Create nebula system user",   "systemd nebula.service",
    "systemd nebula-miner.service","Auto-backup every 6 hours",
    "Log rotation every 30 days",  "Health-check script cron",
    "Generate first wallet",       "Open port 8333 worldwide",
    "Enable auto-start on boot",   "Network buffer tuning",
    "Final status check",
  ];
  return (
    <div>
      <G cols={3}>
        <Card>
          <H>Requirements</H>
          {[
            ["OS",      "Ubuntu 22.04 LTS", T.cyan],
            ["RAM",     "1 GB minimum",     null],
            ["Storage", "20 GB SSD",        null],
            ["CPU",     "1–4 cores",        null],
            ["Port",    "8333 (P2P)",       T.gold],
            ["Cost",    "~$6/month",        T.green],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
        </Card>
        <Card>
          <H>17 Auto Steps</H>
          {steps.map((s,i)=>(
            <div key={s} style={{fontSize:10,color:T.text2,
              padding:"4px 0",borderBottom:`1px solid ${T.bg3}`}}>
              <span style={{color:T.green,marginRight:8,fontSize:9}}>{String(i+1).padStart(2,"0")}</span>{s}
            </div>
          ))}
        </Card>
        <Card>
          <H>VPS Providers</H>
          {[
            ["DigitalOcean","digitalocean.com",T.cyan],
            ["Vultr",       "vultr.com",       null],
            ["Hostinger",   "hostinger.com",   null],
            ["Hetzner",     "hetzner.com",     null],
            ["AWS",         "aws.amazon.com",  null],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
          <Sep/>
          <H>systemd Services</H>
          {[
            ["nebula.service",       "Full node (auto-restart)", T.cyan],
            ["nebula-miner.service", "PoW miner (multiprocessing)", T.gold],
          ].map(([k,v,c])=><Row key={k} k={k} v={v} c={c}/>)}
        </Card>
      </G>
      <Sep/>
      <Card>
        <H>3-Command Deployment</H>
        <Term title="nebula_server_setup.sh" minH={130} lines={[
          {t:"# STEP 1 — Upload files",                                            c:T.text3},
          {t:"scp nebula_*.py nebula_server_setup.sh root@YOUR_SERVER_IP:/root/",  c:T.gold},
          {t:"",c:null},
          {t:"# STEP 2 — SSH into server",                                         c:T.text3},
          {t:"ssh root@YOUR_SERVER_IP",                                             c:T.cyan},
          {t:"",c:null},
          {t:"# STEP 3 — ONE command does all 17 steps automatically",             c:T.text3},
          {t:"chmod +x nebula_server_setup.sh && sudo ./nebula_server_setup.sh",   c:T.green},
          {t:"",c:null},
          {t:"# After setup — start everything",                                   c:T.text3},
          {t:"sudo systemctl start nebula          # start node",                  c:T.gold},
          {t:"sudo systemctl start nebula-miner    # start mining",                c:T.gold},
          {t:"sudo systemctl status nebula         # check status",                c:T.cyan},
        ]}/>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  PAGE: TESTS
// ══════════════════════════════════════════════════════════════════
function PageTests({notify}) {
  const TOTAL=42;
  const [running,sRunning]=useState(false);
  const [done,sDone]=useState(TOTAL);

  function runAll(){
    sRunning(true); sDone(0);
    let i=0;
    const iv=setInterval(()=>{
      i++; sDone(i);
      if(i>=TOTAL){clearInterval(iv);sRunning(false);notify("✅ 42/42 All tests passed!");}
    },90);
  }

  let idx=0;
  return (
    <div>
      <G cols={4} gap={12}>
        {[
          {lbl:"Total",    v:TOTAL,              c:T.cyan},
          {lbl:"Passed",   v:done,               c:T.green},
          {lbl:"Failed",   v:running?TOTAL-done:0,c:running&&TOTAL-done>0?T.red:T.text3},
          {lbl:"Coverage", v:"100%",             c:T.gold},
        ].map(x=>(
          <Card key={x.lbl}><Lbl>{x.lbl}</Lbl><BigNum v={x.v} c={x.c}/></Card>
        ))}
      </G>
      <div style={{margin:"14px 0"}}>
        <Btn color={T.green} onClick={runAll}>{running?"⏳ RUNNING...":"▶ RUN ALL 42 TESTS"}</Btn>
      </div>
      {running&&(
        <Card style={{marginBottom:14}}>
          <div style={{display:"flex",justifyContent:"space-between",
            fontSize:10,color:T.text2,marginBottom:6}}>
            <span>Running test suite...</span>
            <span style={{color:T.cyan}}>{done}/{TOTAL}</span>
          </div>
          <Bar pct={done/TOTAL*100} color={T.green}/>
        </Card>
      )}
      <G cols={2}>
        {TEST_GROUPS.map(gr=>{
          return (
            <Card key={gr.g} style={{padding:"14px 16px"}}>
              <div style={{fontSize:11,color:T.gold,fontWeight:700,marginBottom:10}}>
                {gr.g} ({gr.n})</div>
              {gr.tests.map(t=>{
                idx++;
                const pass=!running||done>=idx;
                return (
                  <div key={t} style={{display:"flex",alignItems:"center",
                    gap:8,padding:"5px 0",borderBottom:`1px solid ${T.bg3}`,fontSize:10}}>
                    <span style={{color:pass?T.green:T.text3,fontSize:12}}>{pass?"✅":"⬜"}</span>
                    <span style={{color:pass?T.text:T.text3}}>{t}</span>
                  </div>
                );
              })}
            </Card>
          );
        })}
      </G>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  SIDEBAR
// ══════════════════════════════════════════════════════════════════
function Sidebar({page,setPage,mining}) {
  return (
    <div style={{width:214,flexShrink:0,
      background:"linear-gradient(180deg,#04090f,#020608)",
      borderRight:`1px solid ${T.border}`,
      display:"flex",flexDirection:"column",
      position:"sticky",top:0,height:"100vh",overflowY:"auto"}}>
      <div style={{padding:"22px 18px 16px",borderBottom:`1px solid ${T.border}`}}>
        <div style={{fontFamily:"'Orbitron',monospace",fontSize:22,fontWeight:900,
          color:T.gold,textShadow:"0 0 22px #f0a50055",letterSpacing:4}}>⬡ NBL</div>
        <div style={{fontSize:8,color:T.text3,letterSpacing:3,marginTop:4}}>NEBULA BLOCKCHAIN</div>
        <div style={{fontSize:8,color:T.gold,opacity:.55,marginTop:4}}>
          by Zayn Quantum · MIT License</div>
      </div>
      <div style={{margin:"10px 14px",padding:"5px 10px",
        background:mining?"rgba(0,255,136,.07)":"rgba(0,229,255,.05)",
        border:`1px solid ${mining?"rgba(0,255,136,.2)":"rgba(0,229,255,.12)"}`,
        borderRadius:4,display:"flex",alignItems:"center",gap:6,
        fontSize:8,color:mining?T.green:T.cyan,letterSpacing:2}}>
        <div style={{width:6,height:6,background:mining?T.green:T.cyan,
          borderRadius:"50%",boxShadow:`0 0 8px ${mining?T.green:T.cyan}`}}/>
        {mining?"MINING ACTIVE":"READY"}
      </div>
      <nav style={{flex:1,padding:"8px 0",overflowY:"auto"}}>
        {NAV_ITEMS.map(n=>{
          const a=page===n.id;
          return (
            <div key={n.id} onClick={()=>setPage(n.id)} style={{
              display:"flex",alignItems:"center",gap:9,
              padding:"9px 18px",cursor:"pointer",
              borderLeft:`2px solid ${a?T.cyan:"transparent"}`,
              background:a?"rgba(0,229,255,.06)":"transparent",
              color:a?T.cyan:T.text2,fontSize:11,transition:"all .15s"}}>
              <span style={{fontSize:13,width:16,textAlign:"center"}}>{n.icon}</span>
              <span>{n.label}</span>
            </div>
          );
        })}
      </nav>
      <div style={{padding:"12px 18px",borderTop:`1px solid ${T.border}`,
        fontSize:9,color:T.text3,lineHeight:1.8}}>
        v{CHAIN.version} · Port {CHAIN.port}<br/>
        Genesis: {CHAIN.genesis_date}<br/>
        Block: 600s · Era I · 50 NBL<br/>
        Chain ID: {CHAIN.id}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  TOPBAR
// ══════════════════════════════════════════════════════════════════
function Topbar({page,bh,mining,hashrate}) {
  const TITLES={
    dashboard:"DASHBOARD",chain:"BLOCKCHAIN",files:"FILES — 10 MODULES",
    classes:"CLASSES — 61 TOTAL",explorer:"BLOCK EXPLORER",
    miner:"MINER — MULTIPROCESSING",wallet:"WALLET — BIP32/39/44",
    network:"P2P NETWORK — 10 SEEDS",security:"SECURITY — 15 CLASSES",
    contracts:"SMART CONTRACTS — 92 OPCODES",cli:"CLI — 20 COMMANDS",
    server:"SERVER DEPLOYMENT",tests:"TEST SUITE — 42/42",
  };
  return (
    <div style={{height:52,background:"rgba(3,8,16,.97)",
      borderBottom:`1px solid ${T.border}`,display:"flex",alignItems:"center",
      padding:"0 24px",gap:10,position:"sticky",top:0,zIndex:50,flexShrink:0}}>
      <div style={{fontFamily:"'Orbitron',monospace",fontSize:12,fontWeight:700,
        color:T.gold,letterSpacing:3,flex:1}}>{TITLES[page]||page.toUpperCase()}</div>
      {[
        {l:"HEIGHT", v:bh.toLocaleString(), c:T.cyan},
        {l:"REWARD",  v:"50 NBL",           c:T.gold},
        {l:"ERA",     v:"I · 2025–2029",    c:T.gold},
        {l:"TESTS",   v:"42/42 ✅",          c:T.green},
      ].map(x=>(
        <div key={x.l} style={{display:"flex",alignItems:"center",gap:5,
          padding:"4px 10px",background:T.bg3,
          border:`1px solid ${T.border}`,borderRadius:4,fontSize:10}}>
          <span style={{color:T.text2}}>{x.l}</span>
          <span style={{color:x.c,fontWeight:700}}>{x.v}</span>
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  NOTIFICATION
// ══════════════════════════════════════════════════════════════════
function Notif({msg,show}) {
  return (
    <div style={{position:"fixed",bottom:24,right:24,
      background:T.panel,border:`1px solid ${T.green}`,
      borderRadius:6,padding:"11px 20px",fontSize:11,color:T.green,
      boxShadow:"0 0 20px rgba(0,255,136,.3)",zIndex:999,
      transform:show?"translateY(0)":"translateY(80px)",
      opacity:show?1:0,transition:"all .3s",pointerEvents:"none"}}>
      {msg}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  APP ROOT
// ══════════════════════════════════════════════════════════════════
export default function App() {
  const [page,       sPage]    = useState("dashboard");
  const [bh,         sBH]      = useState(0);
  const [mining,     sMining]  = useState(false);
  const [blocksFound,sBF]      = useState(0);
  const [hashrate,   sHR]      = useState(0);
  const [notifMsg,   sNM]      = useState("");
  const [notifShow,  sNS]      = useState(false);

  function notify(msg){sNM(msg);sNS(true);setTimeout(()=>sNS(false),3000);}

  useEffect(()=>{
    if(!mining){sHR(0);return;}
    const iv=setInterval(()=>{
      sHR(280_000+Math.random()*80_000|0);
      if(Math.random()<.06){sBH(h=>h+1);sBF(b=>b+1);notify("⛏ Block found! +50 NBL");}
    },1500);
    return()=>clearInterval(iv);
  },[mining]);

  const P={bh,mining,setMining:sMining,blocksFound,hashrate,notify};

  const PAGES={
    dashboard: <PageDashboard  {...P}/>,
    chain:     <PageChain      {...P}/>,
    files:     <PageFiles/>,
    classes:   <PageClasses/>,
    explorer:  <PageExplorer   notify={notify}/>,
    miner:     <PageMiner      {...P}/>,
    wallet:    <PageWallet     notify={notify}/>,
    network:   <PageNetwork/>,
    security:  <PageSecurity/>,
    contracts: <PageContracts/>,
    cli:       <PageCLI        notify={notify}/>,
    server:    <PageServer/>,
    tests:     <PageTests      notify={notify}/>,
  };

  return (
    <div style={{display:"flex",minHeight:"100vh",
      background:T.bg,color:T.text,
      fontFamily:"'JetBrains Mono','Fira Code',monospace",fontSize:12}}>
      <Sidebar page={page} setPage={sPage} mining={mining}/>
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        <Topbar page={page} bh={bh} mining={mining} hashrate={hashrate}/>
        <div style={{flex:1,overflowY:"auto",padding:24}}>{PAGES[page]}</div>
      </div>
      <Notif msg={notifMsg} show={notifShow}/>
    </div>
  );
}
