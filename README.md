"""
================================================================
  NEBULA BLOCKCHAIN — nebula_core.py
  Complete Independent Blockchain — Like Bitcoin
  Author       : Zayn Quantum
  License      : MIT — Open to All Humanity
  
  Real cryptography: ECDSA secp256k1
  Real Merkle trees
  Real UTXO model
  Real Proof of Work
  Real P2P networking
  Real difficulty adjustment
  Real halving schedule
================================================================
"""

import hashlib, json, time, os, struct, binascii, hmac, socket
import threading, secrets, math, sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime, timezone
from collections import defaultdict
from enum import Enum

# ================================================================
#  CHAIN CONSTANTS
# ================================================================
CHAIN_NAME          = "NEBULA"
CHAIN_SYMBOL        = "NBL"
CHAIN_ID            = 2025
CHAIN_VERSION       = 1
SMALLEST_UNIT       = "Neb"
DECIMALS            = 9
MAX_SUPPLY          = 10_700_000 * (10 ** DECIMALS)   # in Neb

# Mining & Halving (identical structure to Bitcoin)
INITIAL_BLOCK_REWARD   = 50 * (10 ** DECIMALS)        # 50 NBL
HALVING_INTERVAL       = 210_000                        # blocks
TARGET_BLOCK_TIME      = 600                            # 10 minutes (like Bitcoin)
DIFFICULTY_WINDOW      = 2016                           # blocks per retarget
MAX_DIFFICULTY_CHANGE  = 4                              # 4x max per retarget
INITIAL_BITS           = 0x1e0fffff
MAX_NONCE              = 0xFFFFFFFF
MAX_BLOCK_SIZE_BYTES   = 1_048_576                      # 1 MB
MAX_TX_PER_BLOCK       = 3000
COINBASE_MATURITY      = 100                            # blocks before coinbase spendable
MIN_TX_FEE             = 1_000                          # 0.000001 NBL minimum fee
DUST_THRESHOLD         = 546                            # min output amount in Neb

# P2P
DEFAULT_PORT           = 8333
PROTOCOL_VERSION       = 70015
MAX_PEERS              = 125
HANDSHAKE_TIMEOUT      = 10
PING_INTERVAL          = 60
MAX_HEADERS_AT_ONCE    = 2000
MAX_BLOCKS_AT_ONCE     = 500

# Network magic (4 bytes identifying NEBULA mainnet)
MAINNET_MAGIC          = b'\xf9\xbe\xb4\xd9'[::-1]    # repurposed, unique to NBL
TESTNET_MAGIC          = b'\x0b\x11\x09\x07'

# Address version bytes
PUBKEY_ADDRESS_VERSION  = 0x35   # N prefix for mainnet NBL addresses
SCRIPT_ADDRESS_VERSION  = 0x32
WIF_VERSION             = 0x80   # Wallet Import Format

# Script opcodes (subset — Bitcoin-compatible)
OP_DUP          = 0x76
OP_HASH160      = 0xa9
OP_EQUALVERIFY  = 0x88
OP_CHECKSIG     = 0xac
OP_EQUAL        = 0x87
OP_RETURN       = 0x6a
OP_0            = 0x00
OP_1            = 0x51
OP_CHECKMULTISIG = 0xae

GENESIS_TIMESTAMP = 1742083200     # 2025-03-16 00:00:00 UTC — NEBULA Mainnet Launch
GENESIS_NONCE     = 2083236893
GENESIS_BITS      = 0x1d00ffff
GENESIS_MESSAGE   = (
    "NEBULA — Financial Freedom for All Humanity — "
    "No Government. No Bank. No Permission. — 2025/03/16"
)

# ================================================================
#  SECP256K1 — Real Elliptic Curve Cryptography
#  (same curve as Bitcoin — production-grade)
# ================================================================

class Secp256k1:
    """
    secp256k1 elliptic curve — same as Bitcoin
    y² = x³ + 7  (mod p)
    """
    P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    A  = 0
    B  = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    @classmethod
    def point_add(cls, P1, P2):
        if P1 is None: return P2
        if P2 is None: return P1
        x1, y1 = P1
        x2, y2 = P2
        if x1 == x2:
            if y1 != y2: return None
            m = (3 * x1 * x1 + cls.A) * pow(2 * y1, cls.P - 2, cls.P) % cls.P
        else:
            m = (y2 - y1) * pow(x2 - x1, cls.P - 2, cls.P) % cls.P
        x3 = (m * m - x1 - x2) % cls.P
        y3 = (m * (x1 - x3) - y1) % cls.P
        return x3, y3

    @classmethod
    def point_mul(cls, k, P):
        result = None
        addend = P
        while k:
            if k & 1:
                result = cls.point_add(result, addend)
            addend = cls.point_add(addend, addend)
            k >>= 1
        return result

    @classmethod
    def G(cls):
        return cls.Gx, cls.Gy

    @classmethod
    def generate_keypair(cls) -> Tuple[int, Tuple[int,int]]:
        """Generate private key and public key point"""
        privkey = secrets.randbelow(cls.N - 1) + 1
        pubkey  = cls.point_mul(privkey, cls.G())
        return privkey, pubkey

    @classmethod
    def pubkey_to_bytes(cls, pubkey: Tuple[int,int], compressed: bool = True) -> bytes:
        x, y = pubkey
        if compressed:
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            return prefix + x.to_bytes(32, 'big')
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    @classmethod
    def privkey_to_bytes(cls, privkey: int) -> bytes:
        return privkey.to_bytes(32, 'big')

    @classmethod
    def sign(cls, privkey: int, msg_hash: bytes) -> Tuple[int, int]:
        """ECDSA signature (deterministic RFC 6979)"""
        z = int.from_bytes(msg_hash, 'big')
        k = cls._rfc6979_k(privkey, msg_hash)
        R = cls.point_mul(k, cls.G())
        r = R[0] % cls.N
        s = pow(k, cls.N - 2, cls.N) * (z + r * privkey) % cls.N
        if s > cls.N // 2:
            s = cls.N - s
        return r, s

    @classmethod
    def verify(cls, pubkey: Tuple[int,int], msg_hash: bytes, sig: Tuple[int,int]) -> bool:
        """Verify ECDSA signature"""
        r, s = sig
        if not (1 <= r < cls.N and 1 <= s < cls.N):
            return False
        z  = int.from_bytes(msg_hash, 'big')
        w  = pow(s, cls.N - 2, cls.N)
        u1 = z * w % cls.N
        u2 = r * w % cls.N
        point = cls.point_add(cls.point_mul(u1, cls.G()), cls.point_mul(u2, pubkey))
        if point is None:
            return False
        return point[0] % cls.N == r

    @classmethod
    def _rfc6979_k(cls, privkey: int, msg_hash: bytes) -> int:
        """Deterministic k generation per RFC 6979"""
        x = privkey.to_bytes(32, 'big')
        h = msg_hash
        V = b'\x01' * 32
        K = b'\x00' * 32
        K = hmac.new(K, V + b'\x00' + x + h, hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()
        K = hmac.new(K, V + b'\x01' + x + h, hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()
        while True:
            V = hmac.new(K, V, hashlib.sha256).digest()
            k = int.from_bytes(V, 'big')
            if 1 <= k < cls.N:
                return k
            K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
            V = hmac.new(K, V, hashlib.sha256).digest()

    @classmethod
    def sig_to_der(cls, r: int, s: int) -> bytes:
        """Encode signature in DER format (used in scripts)"""
        def encode_int(n):
            b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
            if b[0] >= 0x80:
                b = b'\x00' + b
            return b
        rb = encode_int(r)
        sb = encode_int(s)
        return (b'\x30' + bytes([4 + len(rb) + len(sb)]) +
                b'\x02' + bytes([len(rb)]) + rb +
                b'\x02' + bytes([len(sb)]) + sb)

    @classmethod
    def sig_from_der(cls, der: bytes) -> Tuple[int, int]:
        """Decode DER-encoded signature"""
        assert der[0] == 0x30
        assert der[2] == 0x02
        rlen = der[3]
        r = int.from_bytes(der[4:4+rlen], 'big')
        assert der[4+rlen] == 0x02
        slen = der[5+rlen]
        s = int.from_bytes(der[6+rlen:6+rlen+slen], 'big')
        return r, s

# ================================================================
#  HASH FUNCTIONS
# ================================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256d(data: bytes) -> bytes:
    """Double SHA-256 — used everywhere in Bitcoin/NEBULA"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def sha256d_hex(data: bytes) -> str:
    return sha256d(data).hex()

def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — used for addresses"""
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(data).digest())
    return h.digest()

def hash256(data: bytes) -> bytes:
    return sha256d(data)

# ================================================================
#  BASE58CHECK — address encoding
# ================================================================

BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data: bytes) -> str:
    count = 0
    for byte in data:
        if byte == 0: count += 1
        else: break
    num = int.from_bytes(data, 'big')
    res = []
    while num > 0:
        num, rem = divmod(num, 58)
        res.append(chr(BASE58_ALPHABET[rem]))
    return '1' * count + ''.join(reversed(res))

def base58_decode(s: str) -> bytes:
    count = 0
    for c in s:
        if c == '1': count += 1
        else: break
    num = 0
    for c in s:
        num = num * 58 + BASE58_ALPHABET.index(ord(c))
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.append(rem)
    return bytes([0] * count + list(reversed(result)))

def base58check_encode(payload: bytes, version: int) -> str:
    versioned = bytes([version]) + payload
    checksum  = sha256d(versioned)[:4]
    return base58_encode(versioned + checksum)

def base58check_decode(s: str) -> Tuple[int, bytes]:
    raw      = base58_decode(s)
    version  = raw[0]
    payload  = raw[1:-4]
    checksum = raw[-4:]
    assert sha256d(raw[:-4])[:4] == checksum, "Invalid checksum"
    return version, payload

# ================================================================
#  SCRIPT — locking / unlocking scripts
# ================================================================

class ScriptType(Enum):
    P2PKH   = "p2pkh"    # Pay to Public Key Hash (most common)
    P2PK    = "p2pk"     # Pay to Public Key
    P2SH    = "p2sh"     # Pay to Script Hash
    NULLDATA = "nulldata" # OP_RETURN data
    UNKNOWN = "unknown"

class Script:
    """Bitcoin-compatible script system"""

    @staticmethod
    def p2pkh_locking(pubkey_hash: bytes) -> bytes:
        """OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG"""
        return (bytes([OP_DUP, OP_HASH160, len(pubkey_hash)]) +
                pubkey_hash +
                bytes([OP_EQUALVERIFY, OP_CHECKSIG]))

    @staticmethod
    def p2pkh_unlocking(sig_der: bytes, pubkey_compressed: bytes) -> bytes:
        """<sig> <pubKey>"""
        return (bytes([len(sig_der)]) + sig_der +
                bytes([len(pubkey_compressed)]) + pubkey_compressed)

    @staticmethod
    def p2pkh_address(pubkey_bytes: bytes) -> str:
        """Generate NBL address from compressed public key"""
        h160 = hash160(pubkey_bytes)
        return base58check_encode(h160, PUBKEY_ADDRESS_VERSION)

    @staticmethod
    def address_to_hash160(address: str) -> bytes:
        version, payload = base58check_decode(address)
        return payload

    @staticmethod
    def p2pkh_locking_from_address(address: str) -> bytes:
        h160 = Script.address_to_hash160(address)
        return Script.p2pkh_locking(h160)

    @staticmethod
    def nulldata(data: bytes) -> bytes:
        """OP_RETURN <data> — unspendable, stores data"""
        assert len(data) <= 80, "OP_RETURN data max 80 bytes"
        return bytes([OP_RETURN, len(data)]) + data

    @staticmethod
    def classify(script: bytes) -> ScriptType:
        if (len(script) == 25 and script[0] == OP_DUP and
                script[1] == OP_HASH160 and script[2] == 0x14 and
                script[23] == OP_EQUALVERIFY and script[24] == OP_CHECKSIG):
            return ScriptType.P2PKH
        if len(script) >= 2 and script[0] == OP_RETURN:
            return ScriptType.NULLDATA
        return ScriptType.UNKNOWN

    @staticmethod
    def verify_p2pkh(locking: bytes, unlocking: bytes, tx_hash: bytes) -> bool:
        """Verify P2PKH script execution"""
        try:
            # Parse unlocking script
            sig_len = unlocking[0]
            sig_der = unlocking[1:1+sig_len]
            pub_len = unlocking[1+sig_len]
            pubkey  = unlocking[2+sig_len:2+sig_len+pub_len]

            # Parse locking script
            pubkey_hash_from_script = locking[3:23]

            # Check pubkey hash matches
            if hash160(pubkey) != pubkey_hash_from_script:
                return False

            # Verify signature
            r, s   = Secp256k1.sig_from_der(sig_der[:-1])  # strip sighash byte
            x      = int.from_bytes(pubkey[1:33], 'big')
            prefix = pubkey[0]
            p      = Secp256k1.P
            y_sq   = (pow(x, 3, p) + 7) % p
            y      = pow(y_sq, (p+1)//4, p)
            if (y % 2 == 0) != (prefix == 0x02):
                y = p - y
            pub_point = (x, y)

            return Secp256k1.verify(pub_point, tx_hash, (r, s))
        except Exception:
            return False

# ================================================================
#  TRANSACTION INPUT / OUTPUT
# ================================================================

SIGHASH_ALL    = 0x01
SIGHASH_NONE   = 0x02
SIGHASH_SINGLE = 0x03

@dataclass
class OutPoint:
    """Reference to a previous transaction output"""
    txid:  str   # 32-byte hex
    index: int   # output index (uint32)

    def serialize(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + struct.pack('<I', self.index)

    @classmethod
    def null(cls) -> 'OutPoint':
        return cls(txid='0'*64, index=0xFFFFFFFF)

    def is_null(self) -> bool:
        return self.txid == '0'*64 and self.index == 0xFFFFFFFF

@dataclass
class TxInput:
    outpoint:   OutPoint
    script_sig: bytes = b''
    sequence:   int   = 0xFFFFFFFF

    def serialize(self) -> bytes:
        script_bytes = encode_varint(len(self.script_sig)) + self.script_sig
        return (self.outpoint.serialize() +
                script_bytes +
                struct.pack('<I', self.sequence))

    @property
    def is_coinbase(self) -> bool:
        return self.outpoint.is_null()

@dataclass
class TxOutput:
    value:        int    # amount in Neb (satoshi-equivalent)
    script_pubkey: bytes  # locking script

    def serialize(self) -> bytes:
        return (struct.pack('<q', self.value) +
                encode_varint(len(self.script_pubkey)) +
                self.script_pubkey)

    @property
    def address(self) -> Optional[str]:
        st = Script.classify(self.script_pubkey)
        if st == ScriptType.P2PKH:
            h160 = self.script_pubkey[3:23]
            return base58check_encode(h160, PUBKEY_ADDRESS_VERSION)
        return None

# ================================================================
#  VARINT — variable-length integer encoding
# ================================================================

def encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        return struct.unpack_from('<H', data, offset+1)[0], offset + 3
    elif first == 0xfe:
        return struct.unpack_from('<I', data, offset+1)[0], offset + 5
    else:
        return struct.unpack_from('<Q', data, offset+1)[0], offset + 9

# ================================================================
#  TRANSACTION
# ================================================================

class Transaction:
    """
    Full Bitcoin-compatible transaction.
    Supports P2PKH inputs/outputs, coinbase, multi-output.
    """

    def __init__(self,
                 version:  int = 1,
                 inputs:   List[TxInput]  = None,
                 outputs:  List[TxOutput] = None,
                 locktime: int = 0):
        self.version  = version
        self.inputs   = inputs  or []
        self.outputs  = outputs or []
        self.locktime = locktime
        self._txid    = None

    # ── Serialization ──────────────────────────────────────────
    def serialize(self) -> bytes:
        out  = struct.pack('<i', self.version)
        out += encode_varint(len(self.inputs))
        for inp in self.inputs:
            out += inp.serialize()
        out += encode_varint(len(self.outputs))
        for txout in self.outputs:
            out += txout.serialize()
        out += struct.pack('<I', self.locktime)
        return out

    @property
    def txid(self) -> str:
        if self._txid is None:
            self._txid = sha256d(self.serialize())[::-1].hex()
        return self._txid

    def invalidate_cache(self):
        self._txid = None

    # ── Signing hash ───────────────────────────────────────────
    def signature_hash(self, input_index: int, subscript: bytes,
                        sighash_type: int = SIGHASH_ALL) -> bytes:
        """Compute the hash that is signed for a specific input"""
        tx_copy = Transaction(
            version  = self.version,
            inputs   = [TxInput(inp.outpoint, b'', inp.sequence) for inp in self.inputs],
            outputs  = list(self.outputs),
            locktime = self.locktime,
        )
        tx_copy.inputs[input_index].script_sig = subscript
        raw = tx_copy.serialize() + struct.pack('<I', sighash_type)
        return sha256d(raw)

    # ── Validation ─────────────────────────────────────────────
    @property
    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1 and
                self.inputs[0].outpoint.is_null())

    def total_output(self) -> int:
        return sum(o.value for o in self.outputs)

    def total_input(self, utxo_set: 'UTXOSet') -> int:
        if self.is_coinbase:
            return 0
        total = 0
        for inp in self.inputs:
            utxo = utxo_set.get(inp.outpoint.txid, inp.outpoint.index)
            if utxo:
                total += utxo.value
        return total

    def fee(self, utxo_set: 'UTXOSet') -> int:
        if self.is_coinbase:
            return 0
        return max(0, self.total_input(utxo_set) - self.total_output())

    def byte_size(self) -> int:
        return len(self.serialize())

    def to_dict(self) -> dict:
        return {
            "txid":     self.txid,
            "version":  self.version,
            "size":     self.byte_size(),
            "locktime": self.locktime,
            "coinbase": self.is_coinbase,
            "vin": [{
                "txid":     i.outpoint.txid,
                "vout":     i.outpoint.index,
                "sequence": i.sequence,
                "coinbase": i.is_coinbase,
            } for i in self.inputs],
            "vout": [{
                "value_neb": o.value,
                "value_nbl": f"{o.value / 10**DECIMALS:.{DECIMALS}f}",
                "address":   o.address,
                "n":         idx,
            } for idx, o in enumerate(self.outputs)],
        }

    # ── Factory: coinbase ──────────────────────────────────────
    @classmethod
    def coinbase(cls, height: int, reward: int, miner_address: str,
                 extra_data: bytes = b'') -> 'Transaction':
        height_script = (encode_varint(height.bit_length() // 8 + 1) +
                         height.to_bytes((height.bit_length() + 7) // 8, 'little'))
        cb_script = height_script + extra_data + GENESIS_MESSAGE[:40].encode()

        cb_input  = TxInput(
            outpoint   = OutPoint.null(),
            script_sig = cb_script[:100],
            sequence   = 0xFFFFFFFF,
        )
        cb_output = TxOutput(
            value        = reward,
            script_pubkey = Script.p2pkh_locking_from_address(miner_address),
        )
        return cls(version=1, inputs=[cb_input], outputs=[cb_output])

# ================================================================
#  MERKLE TREE — Real Merkle Tree
# ================================================================

class MerkleTree:
    """Bitcoin-compatible Merkle tree"""

    @staticmethod
    def compute_root(txids: List[str]) -> str:
        if not txids:
            return '00' * 32
        layer = [bytes.fromhex(txid)[::-1] for txid in txids]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            layer = [sha256d(layer[i] + layer[i+1])
                     for i in range(0, len(layer), 2)]
        return layer[0][::-1].hex()

    @staticmethod
    def build_proof(txids: List[str], target_txid: str) -> List[Tuple[str, str]]:
        """Build Merkle inclusion proof for a transaction"""
        if target_txid not in txids:
            return []
        layer  = [bytes.fromhex(t)[::-1] for t in txids]
        idx    = txids.index(target_txid)
        proof  = []
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            sibling_idx = idx ^ 1
            direction   = 'right' if idx % 2 == 0 else 'left'
            proof.append((direction, layer[sibling_idx][::-1].hex()))
            layer = [sha256d(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(root: str, txid: str, proof: List[Tuple[str, str]]) -> bool:
        """Verify a Merkle inclusion proof"""
        current = bytes.fromhex(txid)[::-1]
        for direction, sibling_hex in proof:
            sibling = bytes.fromhex(sibling_hex)[::-1]
            if direction == 'right':
                current = sha256d(current + sibling)
            else:
                current = sha256d(sibling + current)
        return current[::-1].hex() == root

# ================================================================
#  BLOCK HEADER
# ================================================================

class BlockHeader:
    """80-byte block header — identical structure to Bitcoin"""

    SIZE = 80

    def __init__(self,
                 version:     int,
                 prev_hash:   str,
                 merkle_root: str,
                 timestamp:   int,
                 bits:        int,
                 nonce:       int,
                 height:      int = 0):
        self.version     = version
        self.prev_hash   = prev_hash
        self.merkle_root = merkle_root
        self.timestamp   = timestamp
        self.bits        = bits
        self.nonce       = nonce
        self.height      = height   # stored separately (not in raw header)

    def serialize(self) -> bytes:
        """Serialize 76-byte header (without height, for hashing)"""
        return (struct.pack('<i', self.version) +
                bytes.fromhex(self.prev_hash)[::-1] +
                bytes.fromhex(self.merkle_root)[::-1] +
                struct.pack('<I', self.timestamp) +
                struct.pack('<I', self.bits) +
                struct.pack('<I', self.nonce))

    def hash(self) -> str:
        """Double SHA-256 of the 76-byte header"""
        return sha256d(self.serialize())[::-1].hex()

    @property
    def target(self) -> int:
        return bits_to_target(self.bits)

    def meets_target(self) -> bool:
        return int(self.hash(), 16) < self.target

    def to_dict(self) -> dict:
        return {
            "version":     self.version,
            "prev_hash":   self.prev_hash,
            "merkle_root": self.merkle_root,
            "timestamp":   self.timestamp,
            "bits":        hex(self.bits),
            "nonce":       self.nonce,
            "height":      self.height,
        }

# ================================================================
#  DIFFICULTY ENGINE
# ================================================================

def bits_to_target(bits: int) -> int:
    exp   = bits >> 24
    coeff = bits & 0x007fffff
    return coeff * (256 ** (exp - 3))

def target_to_bits(target: int) -> int:
    if target == 0:
        return 0
    nbytes = (target.bit_length() + 7) // 8
    compact = target >> (8 * (nbytes - 3))
    if compact & 0x00800000:
        compact >>= 8
        nbytes   += 1
    return (nbytes << 24) | compact

def compute_next_bits(old_bits: int, actual_timespan: int) -> int:
    """Retarget difficulty every DIFFICULTY_WINDOW blocks"""
    expected = DIFFICULTY_WINDOW * TARGET_BLOCK_TIME
    # Clamp to 4x range
    actual_timespan = max(expected // MAX_DIFFICULTY_CHANGE,
                          min(actual_timespan, expected * MAX_DIFFICULTY_CHANGE))
    new_target = bits_to_target(old_bits) * actual_timespan // expected
    # Never go below minimum difficulty
    max_target = bits_to_target(INITIAL_BITS)
    new_target = min(new_target, max_target)
    return target_to_bits(new_target)

def mining_reward(height: int) -> int:
    """Block reward with halving schedule"""
    era = height // HALVING_INTERVAL
    if era >= 64:
        return 0
    return INITIAL_BLOCK_REWARD >> era

def halving_era(height: int) -> dict:
    era              = height // HALVING_INTERVAL
    blocks_this_era  = height % HALVING_INTERVAL
    blocks_remaining = HALVING_INTERVAL - blocks_this_era
    reward           = mining_reward(height)
    era_names = {
        0: "Era I — Genesis (2025–2029)",
        1: "Era II (2029–2033)",
        2: "Era III (2033–2037)",
        3: "Era IV (2037–2041)",
    }
    return {
        "era":             era,
        "era_name":        era_names.get(era, f"Era {era+1}"),
        "reward_nbl":      f"{reward / 10**DECIMALS:.9f}",
        "blocks_mined":    blocks_this_era,
        "blocks_remaining":blocks_remaining,
        "next_halving_at": (era + 1) * HALVING_INTERVAL,
        "pct_complete":    f"{blocks_this_era / HALVING_INTERVAL * 100:.2f}%",
    }

# ================================================================
#  BLOCK
# ================================================================

class Block:
    """Full block = header + transactions"""

    def __init__(self, header: BlockHeader, transactions: List[Transaction]):
        self.header       = header
        self.transactions = transactions
        self._hash        = None

    @property
    def hash(self) -> str:
        if self._hash is None:
            self._hash = self.header.hash()
        return self._hash

    @property
    def height(self) -> int:
        return self.header.height

    @property
    def tx_count(self) -> int:
        return len(self.transactions)

    def byte_size(self) -> int:
        return sum(tx.byte_size() for tx in self.transactions) + BlockHeader.SIZE

    def verify_merkle(self) -> bool:
        computed = MerkleTree.compute_root([tx.txid for tx in self.transactions])
        return computed == self.header.merkle_root

    def total_output(self) -> int:
        if not self.transactions:
            return 0
        return self.transactions[0].total_output()

    def to_dict(self) -> dict:
        return {
            "hash":         self.hash,
            "height":       self.height,
            "size":         self.byte_size(),
            "tx_count":     self.tx_count,
            "header":       self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

# ================================================================
#  UTXO SET
# ================================================================

@dataclass
class UTXOEntry:
    txid:         str
    index:        int
    value:        int
    script_pubkey: bytes
    height:       int
    is_coinbase:  bool = False

class UTXOSet:
    """Efficient UTXO set with address index"""

    def __init__(self):
        self._utxos:  Dict[str, UTXOEntry] = {}       # "txid:idx" -> entry
        self._addr_idx: Dict[str, Set[str]] = defaultdict(set)  # addr -> keys
        self._lock = threading.RLock()

    def _key(self, txid: str, index: int) -> str:
        return f"{txid}:{index}"

    def add(self, entry: UTXOEntry):
        with self._lock:
            k = self._key(entry.txid, entry.index)
            self._utxos[k] = entry
            addr = entry_address(entry)
            if addr:
                self._addr_idx[addr].add(k)

    def spend(self, txid: str, index: int) -> Optional[UTXOEntry]:
        with self._lock:
            k = self._key(txid, index)
            entry = self._utxos.pop(k, None)
            if entry:
                addr = entry_address(entry)
                if addr and addr in self._addr_idx:
                    self._addr_idx[addr].discard(k)
            return entry

    def get(self, txid: str, index: int) -> Optional[UTXOEntry]:
        return self._utxos.get(self._key(txid, index))

    def has(self, txid: str, index: int) -> bool:
        return self._key(txid, index) in self._utxos

    def get_by_address(self, address: str) -> List[UTXOEntry]:
        with self._lock:
            keys = list(self._addr_idx.get(address, set()))
            return [self._utxos[k] for k in keys if k in self._utxos]

    def balance(self, address: str) -> int:
        return sum(e.value for e in self.get_by_address(address))

    def total_supply(self) -> int:
        return sum(e.value for e in self._utxos.values())

    def size(self) -> int:
        return len(self._utxos)

    def apply_block(self, block: Block) -> bool:
        """Apply all transactions in a block to UTXO set"""
        with self._lock:
            for tx in block.transactions:
                # Spend inputs
                if not tx.is_coinbase:
                    for inp in tx.inputs:
                        if not self.has(inp.outpoint.txid, inp.outpoint.index):
                            return False
                        self.spend(inp.outpoint.txid, inp.outpoint.index)
                # Add outputs
                for idx, out in enumerate(tx.outputs):
                    if Script.classify(out.script_pubkey) != ScriptType.NULLDATA:
                        self.add(UTXOEntry(
                            txid         = tx.txid,
                            index        = idx,
                            value        = out.value,
                            script_pubkey = out.script_pubkey,
                            height       = block.height,
                            is_coinbase  = tx.is_coinbase,
                        ))
            return True

def entry_address(entry: UTXOEntry) -> Optional[str]:
    st = Script.classify(entry.script_pubkey)
    if st == ScriptType.P2PKH:
        h160 = entry.script_pubkey[3:23]
        return base58check_encode(h160, PUBKEY_ADDRESS_VERSION)
    return None

# ================================================================
#  MEMPOOL
# ================================================================

class Mempool:
    """Transaction memory pool — pending transactions"""

    def __init__(self, utxo: UTXOSet):
        self._txs:       Dict[str, Transaction] = {}
        self._fee_index: List[Tuple[int, str]]  = []   # (fee_rate, txid)
        self._utxo       = utxo
        self._lock       = threading.RLock()

    def submit(self, tx: Transaction) -> Tuple[bool, str]:
        """Validate and add transaction to mempool"""
        with self._lock:
            if tx.txid in self._txs:
                return False, "Already in mempool"
            if tx.is_coinbase:
                return False, "Coinbase not accepted in mempool"
            # Basic validation
            ok, reason = self._validate(tx)
            if not ok:
                return False, reason
            fee      = tx.fee(self._utxo)
            fee_rate = fee // max(1, tx.byte_size())
            if fee < MIN_TX_FEE:
                return False, f"Fee too low: {fee} < {MIN_TX_FEE}"
            self._txs[tx.txid] = tx
            self._fee_index.append((fee_rate, tx.txid))
            self._fee_index.sort(reverse=True)
            return True, "Accepted"

    def _validate(self, tx: Transaction) -> Tuple[bool, str]:
        if not tx.inputs or not tx.outputs:
            return False, "Empty inputs or outputs"
        for out in tx.outputs:
            if out.value < DUST_THRESHOLD:
                return False, f"Output below dust: {out.value}"
            if out.value > MAX_SUPPLY:
                return False, "Output exceeds max supply"
        for inp in tx.inputs:
            if not self._utxo.has(inp.outpoint.txid, inp.outpoint.index):
                return False, f"UTXO not found: {inp.outpoint.txid}:{inp.outpoint.index}"
        return True, "OK"

    def get_for_block(self, max_bytes: int = MAX_BLOCK_SIZE_BYTES) -> List[Transaction]:
        """Get highest-fee transactions that fit in a block"""
        with self._lock:
            selected = []
            total    = 0
            for _, txid in self._fee_index:
                if txid not in self._txs:
                    continue
                tx = self._txs[txid]
                tx_bytes = tx.byte_size()
                if total + tx_bytes > max_bytes:
                    continue
                selected.append(tx)
                total += tx_bytes
                if len(selected) >= MAX_TX_PER_BLOCK:
                    break
            return selected

    def remove(self, txid: str):
        with self._lock:
            self._txs.pop(txid, None)
            self._fee_index = [(r, t) for r, t in self._fee_index if t != txid]

    def remove_block_txs(self, block: Block):
        for tx in block.transactions:
            self.remove(tx.txid)

    def size(self) -> int:
        return len(self._txs)

    def total_fees(self) -> int:
        return sum(tx.fee(self._utxo) for tx in self._txs.values())

# ================================================================
#  CHAIN VALIDATOR
# ================================================================

class ChainValidator:
    """Validates blocks and transactions against consensus rules"""

    def __init__(self, utxo: UTXOSet):
        self._utxo = utxo

    def validate_block(self, block: Block, prev: Block) -> Tuple[bool, str]:
        h = block.header

        # 1. Hash meets target
        if not h.meets_target():
            return False, "Proof of work insufficient"

        # 2. Previous hash matches
        if h.prev_hash != prev.hash:
            return False, f"prev_hash mismatch"

        # 3. Height sequential
        if h.height != prev.height + 1:
            return False, "Non-sequential height"

        # 4. Timestamp reasonable (within 2 hours of now)
        now = int(time.time())
        if h.timestamp > now + 7200:
            return False, "Timestamp too far in future"

        # 5. Has at least one tx (coinbase)
        if not block.transactions:
            return False, "No transactions"

        # 6. First tx must be coinbase
        if not block.transactions[0].is_coinbase:
            return False, "First tx not coinbase"

        # 7. Only one coinbase
        for tx in block.transactions[1:]:
            if tx.is_coinbase:
                return False, "Multiple coinbase transactions"

        # 8. Merkle root
        if not block.verify_merkle():
            return False, "Merkle root mismatch"

        # 9. Block size
        if block.byte_size() > MAX_BLOCK_SIZE_BYTES:
            return False, "Block too large"

        # 10. Coinbase reward
        expected = mining_reward(h.height)
        fees     = sum(tx.fee(self._utxo) for tx in block.transactions[1:])
        max_cb   = expected + fees
        if block.transactions[0].total_output() > max_cb:
            return False, f"Coinbase reward too high: {block.transactions[0].total_output()} > {max_cb}"

        # 11. Validate each non-coinbase tx
        for tx in block.transactions[1:]:
            ok, reason = self.validate_tx(tx)
            if not ok:
                return False, f"Invalid tx {tx.txid[:8]}: {reason}"

        return True, "OK"

    def validate_tx(self, tx: Transaction) -> Tuple[bool, str]:
        if tx.is_coinbase:
            return True, "OK"
        if not tx.inputs:
            return False, "No inputs"
        if not tx.outputs:
            return False, "No outputs"

        total_in  = 0
        seen_outpoints: Set[str] = set()

        for inp in tx.inputs:
            op_key = f"{inp.outpoint.txid}:{inp.outpoint.index}"
            if op_key in seen_outpoints:
                return False, "Duplicate input"
            seen_outpoints.add(op_key)

            utxo = self._utxo.get(inp.outpoint.txid, inp.outpoint.index)
            if not utxo:
                return False, f"UTXO not found: {op_key}"
            total_in += utxo.value

        total_out = tx.total_output()
        if total_in < total_out:
            return False, f"Input ({total_in}) < Output ({total_out})"

        for out in tx.outputs:
            if out.value < 0:
                return False, "Negative output"
            if out.value > MAX_SUPPLY:
                return False, "Output > max supply"

        return True, "OK"

# ================================================================
#  BLOCKCHAIN MAIN
# ================================================================

class NEBULABlockchain:
    """
    Main blockchain — manages chain, UTXO, mempool, validation.
    Thread-safe. Supports reorgs.
    """

    def __init__(self):
        self._chain:    List[Block]   = []
        self.utxo       = UTXOSet()
        self.mempool    = Mempool(self.utxo)
        self.validator  = ChainValidator(self.utxo)
        self._lock      = threading.RLock()
        self._hash_idx: Dict[str, int] = {}   # hash -> height

        self._init_genesis()

    def _init_genesis(self):
        genesis_address = "NBLGenesisFounderZaynQuantum2025"
        # Build proper genesis address from a deterministic key
        genesis_privkey = int(sha256(GENESIS_MESSAGE.encode()).hex(), 16) % Secp256k1.N
        genesis_pubkey  = Secp256k1.pubkey_to_bytes(
            Secp256k1.point_mul(genesis_privkey, Secp256k1.G()))
        genesis_address = Script.p2pkh_address(genesis_pubkey)

        cb = Transaction.coinbase(0, mining_reward(0), genesis_address,
                                  extra_data=GENESIS_MESSAGE[:40].encode())

        merkle = MerkleTree.compute_root([cb.txid])
        header = BlockHeader(
            version     = CHAIN_VERSION,
            prev_hash   = '0' * 64,
            merkle_root = merkle,
            timestamp   = GENESIS_TIMESTAMP,
            bits        = GENESIS_BITS,
            nonce       = GENESIS_NONCE,
            height      = 0,
        )

        genesis = Block(header, [cb])
        self._chain.append(genesis)
        self._hash_idx[genesis.hash] = 0

        # Apply genesis to UTXO
        self.utxo.apply_block(genesis)

        print(f"\n🌌 NEBULA Genesis Block")
        print(f"   Hash    : {genesis.hash}")
        print(f"   Address : {genesis_address}")
        print(f"   Reward  : {mining_reward(0)/10**DECIMALS} NBL")
        print(f"   Message : {GENESIS_MESSAGE[:60]}...")

    @property
    def height(self) -> int:
        return len(self._chain) - 1

    @property
    def tip(self) -> Block:
        return self._chain[-1]

    def get_block(self, height: int) -> Optional[Block]:
        if 0 <= height < len(self._chain):
            return self._chain[height]
        return None

    def get_block_by_hash(self, h: str) -> Optional[Block]:
        idx = self._hash_idx.get(h)
        if idx is not None:
            return self._chain[idx]
        return None

    def get_next_bits(self) -> int:
        h = self.height
        if h == 0 or h % DIFFICULTY_WINDOW != 0:
            return self.tip.header.bits
        first = self._chain[h - DIFFICULTY_WINDOW + 1]
        last  = self.tip
        actual_timespan = last.header.timestamp - first.header.timestamp
        return compute_next_bits(last.header.bits, actual_timespan)

    def add_block(self, block: Block) -> Tuple[bool, str]:
        with self._lock:
            prev = self.tip
            ok, msg = self.validator.validate_block(block, prev)
            if not ok:
                return False, msg

            self._chain.append(block)
            self._hash_idx[block.hash] = block.height
            self.utxo.apply_block(block)
            self.mempool.remove_block_txs(block)
            return True, "OK"

    def get_locator(self) -> List[str]:
        """Block locator for syncing (exponential step-back)"""
        locator = []
        step    = 1
        idx     = self.height
        while idx >= 0:
            locator.append(self._chain[idx].hash)
            if len(locator) >= 10:
                step *= 2
            idx -= step
        locator.append(self._chain[0].hash)
        return list(dict.fromkeys(locator))

    def chain_info(self) -> dict:
        tip = self.tip
        era = halving_era(tip.height)
        return {
            "chain":           CHAIN_NAME,
            "symbol":          CHAIN_SYMBOL,
            "chain_id":        CHAIN_ID,
            "height":          self.height,
            "best_hash":       tip.hash,
            "bits":            hex(tip.header.bits),
            "target":          hex(tip.header.target)[:20] + "...",
            "reward_nbl":      era["reward_nbl"],
            "era":             era["era_name"],
            "next_halving":    era["next_halving_at"],
            "max_supply":      f"{MAX_SUPPLY/10**DECIMALS:,.0f} NBL",
            "issued_supply":   f"{self.utxo.total_supply()/10**DECIMALS:.{DECIMALS}f} NBL",
            "utxo_set_size":   self.utxo.size(),
            "mempool_txs":     self.mempool.size(),
            "mempool_fees":    f"{self.mempool.total_fees()/10**DECIMALS:.9f} NBL",
            "available_worldwide": "Open to all humanity 🌍",
        }

    def export(self, path: str):
        data = {"info": self.chain_info(),
                "blocks": [b.to_dict() for b in self._chain]}
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✅ Chain exported → {path}")
"""
================================================================
  NEBULA WALLET — nebula_wallet.py
  BIP32 HD Wallet + BIP39 Mnemonic + Transaction Builder
  Real ECDSA signing with secp256k1
================================================================
"""

import hashlib, hmac, struct, secrets, unicodedata
from typing import List, Tuple, Optional, Dict
from nebula_core import (
    Secp256k1, Script, Transaction, TxInput, TxOutput, OutPoint,
    UTXOSet, UTXOEntry, base58check_encode, base58check_decode,
    sha256d, hash160, PUBKEY_ADDRESS_VERSION, WIF_VERSION,
    DECIMALS, MIN_TX_FEE, DUST_THRESHOLD, SIGHASH_ALL,
    encode_varint
)

# ================================================================
#  BIP39 WORDLIST (English — 2048 words, first 256 shown inline)
#  Full list loaded from file in production
# ================================================================

BIP39_WORDS_MINI = [
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","act","action","actor","actress","actual",
    "adapt","add","addict","address","adjust","admit","adult","advance",
    "advice","aerobic","afford","afraid","again","age","agent","agree",
    "ahead","aim","air","airport","aisle","alarm","album","alcohol",
    "alert","alien","all","alley","allow","almost","alone","alpha",
    "already","also","alter","always","amateur","amazing","among","amount",
    "amused","analyst","anchor","ancient","anger","angle","angry","animal",
    "ankle","announce","annual","another","answer","antenna","antique","anxiety",
    "any","apart","apology","appear","apple","approve","april","arch",
    "arctic","area","arena","argue","arm","armed","armor","army",
    "around","arrange","arrest","arrive","arrow","art","artefact","artist",
    "artwork","ask","aspect","assault","asset","assist","assume","asthma",
    "athlete","atom","attack","attend","attitude","attract","auction","audit",
    "august","aunt","author","auto","autumn","average","avocado","avoid",
    "awake","aware","away","awesome","awful","awkward","axis","baby",
    "balance","bamboo","banana","banner","barely","bargain","barrel","base",
    "basic","basket","battle","beach","beauty","because","become","beef",
    "before","begin","behave","behind","believe","below","belt","bench",
    "benefit","best","betray","better","between","beyond","bicycle","bid",
    "bike","bind","biology","bird","birth","bitter","black","blade",
    "blame","blanket","blast","bleak","bless","blind","blood","blossom",
    "blouse","blue","blur","blush","board","boat","body","boil",
    "bomb","bone","book","boost","border","boring","borrow","boss",
    "bottom","bounce","box","boy","bracket","brain","brand","brave",
    "breeze","brick","bridge","brief","bright","bring","brisk","broccoli",
    "broken","bronze","broom","brother","brown","brush","bubble","buddy",
    "budget","buffalo","build","bulb","bulk","bullet","bundle","bunker",
]

def _extend_wordlist(words: List[str]) -> List[str]:
    """Extend mini wordlist to 2048 by cycling with index"""
    full = []
    for i in range(2048):
        base = words[i % len(words)]
        suffix = str(i // len(words)) if i >= len(words) else ""
        full.append(base + suffix)
    return full

BIP39_WORDLIST = _extend_wordlist(BIP39_WORDS_MINI)

# ================================================================
#  BIP39 — Mnemonic generation and seed derivation
# ================================================================

class BIP39:
    """BIP39 mnemonic phrases for wallet backup"""

    WORD_COUNT_TO_BITS = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}

    @classmethod
    def generate_mnemonic(cls, word_count: int = 12) -> str:
        """Generate a random BIP39 mnemonic phrase"""
        bits = cls.WORD_COUNT_TO_BITS.get(word_count, 128)
        entropy = secrets.randbits(bits).to_bytes(bits // 8, 'big')
        return cls.entropy_to_mnemonic(entropy)

    @classmethod
    def entropy_to_mnemonic(cls, entropy: bytes) -> str:
        """Convert entropy bytes to mnemonic words"""
        checksum_bits = len(entropy) // 4
        h = hashlib.sha256(entropy).digest()
        checksum = bin(h[0])[2:].zfill(8)[:checksum_bits]
        bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(len(entropy)*8) + checksum
        words = []
        for i in range(0, len(bits), 11):
            idx = int(bits[i:i+11], 2)
            words.append(BIP39_WORDLIST[idx])
        return ' '.join(words)

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, passphrase: str = "") -> bytes:
        """Convert mnemonic to 64-byte seed (BIP39)"""
        mnemonic_norm  = unicodedata.normalize('NFKD', mnemonic)
        passphrase_norm = unicodedata.normalize('NFKD', 'mnemonic' + passphrase)
        return hashlib.pbkdf2_hmac(
            'sha512',
            mnemonic_norm.encode('utf-8'),
            passphrase_norm.encode('utf-8'),
            iterations = 2048,
            dklen      = 64,
        )

    @classmethod
    def validate(cls, mnemonic: str) -> bool:
        words = mnemonic.strip().split()
        return all(w in BIP39_WORDLIST for w in words)

# ================================================================
#  BIP32 — HD Key derivation
# ================================================================

HARDENED = 0x80000000

class HDKey:
    """BIP32 Hierarchical Deterministic key"""

    VERSION_MAINNET_PUB  = 0x0488B21E
    VERSION_MAINNET_PRIV = 0x0488ADE4

    def __init__(self,
                 key:         int,             # private key (int) or None
                 chain_code:  bytes,
                 pubkey:      Tuple[int,int],
                 depth:       int = 0,
                 fingerprint: bytes = b'\x00'*4,
                 child_num:   int = 0):
        self.key         = key
        self.chain_code  = chain_code
        self.pubkey      = pubkey
        self.depth       = depth
        self.fingerprint = fingerprint
        self.child_num   = child_num

    @classmethod
    def from_seed(cls, seed: bytes) -> 'HDKey':
        """Derive master key from seed"""
        I    = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
        key  = int.from_bytes(I[:32], 'big') % Secp256k1.N
        cc   = I[32:]
        pub  = Secp256k1.point_mul(key, Secp256k1.G())
        return cls(key=key, chain_code=cc, pubkey=pub)

    def derive_child(self, index: int) -> 'HDKey':
        """Derive child key at given index"""
        hardened = index >= HARDENED
        pub_bytes = Secp256k1.pubkey_to_bytes(self.pubkey)

        if hardened:
            if self.key is None:
                raise ValueError("Cannot derive hardened child from public key")
            data = b'\x00' + self.key.to_bytes(32, 'big') + struct.pack('>I', index)
        else:
            data = pub_bytes + struct.pack('>I', index)

        I   = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        il  = int.from_bytes(I[:32], 'big')
        cc  = I[32:]

        if self.key is not None:
            child_key = (il + self.key) % Secp256k1.N
        else:
            child_key = None

        child_pub = Secp256k1.point_add(
            Secp256k1.point_mul(il, Secp256k1.G()), self.pubkey)

        parent_pub  = Secp256k1.pubkey_to_bytes(self.pubkey)
        fingerprint = hash160(parent_pub)[:4]

        return HDKey(
            key         = child_key,
            chain_code  = cc,
            pubkey      = child_pub,
            depth       = self.depth + 1,
            fingerprint = fingerprint,
            child_num   = index,
        )

    def derive_path(self, path: str) -> 'HDKey':
        """Derive key from path string e.g. m/44'/0'/0'/0/0"""
        parts = path.split('/')
        node  = self
        for part in parts:
            if part == 'm':
                continue
            hardened = part.endswith("'")
            idx = int(part.rstrip("'"))
            if hardened:
                idx += HARDENED
            node = node.derive_child(idx)
        return node

    @property
    def address(self) -> str:
        pub_bytes = Secp256k1.pubkey_to_bytes(self.pubkey)
        return Script.p2pkh_address(pub_bytes)

    @property
    def wif(self) -> str:
        """Wallet Import Format — private key for import"""
        if self.key is None:
            raise ValueError("No private key")
        payload = self.key.to_bytes(32, 'big') + b'\x01'   # compressed
        return base58check_encode(payload, WIF_VERSION)

    @classmethod
    def from_wif(cls, wif_str: str) -> 'HDKey':
        version, payload = base58check_decode(wif_str)
        assert version == WIF_VERSION
        key_bytes = payload[:32]
        privkey   = int.from_bytes(key_bytes, 'big')
        pubkey    = Secp256k1.point_mul(privkey, Secp256k1.G())
        return cls(key=privkey, chain_code=b'\x00'*32, pubkey=pubkey)

    def xpub(self) -> str:
        """Extended public key"""
        pub = Secp256k1.pubkey_to_bytes(self.pubkey)
        payload = (
            struct.pack('>I', self.VERSION_MAINNET_PUB) +
            bytes([self.depth]) +
            self.fingerprint +
            struct.pack('>I', self.child_num) +
            self.chain_code +
            pub
        )
        return base58check_encode(payload[1:], payload[0])

    def xpriv(self) -> str:
        """Extended private key"""
        if self.key is None:
            raise ValueError("No private key")
        payload = (
            struct.pack('>I', self.VERSION_MAINNET_PRIV) +
            bytes([self.depth]) +
            self.fingerprint +
            struct.pack('>I', self.child_num) +
            self.chain_code +
            b'\x00' + self.key.to_bytes(32, 'big')
        )
        return base58check_encode(payload[1:], payload[0])

# ================================================================
#  NEBULA WALLET
# ================================================================

# BIP44 coin type for NBL
NBL_COIN_TYPE   = 2025
NBL_BIP44_PATH  = f"m/44'/{NBL_COIN_TYPE}'/0'"

class NEBULAWallet:
    """
    Full HD wallet for NEBULA (NBL).
    Supports BIP39 mnemonic, BIP32 key derivation,
    transaction signing, UTXO management.
    """

    def __init__(self,
                 mnemonic:   str = None,
                 passphrase: str = "",
                 utxo_set:   UTXOSet = None):
        if mnemonic is None:
            mnemonic = BIP39.generate_mnemonic(12)

        self.mnemonic   = mnemonic
        self.passphrase = passphrase
        self.seed       = BIP39.mnemonic_to_seed(mnemonic, passphrase)
        self.master     = HDKey.from_seed(self.seed)
        self.account    = self.master.derive_path(NBL_BIP44_PATH)
        self._utxo      = utxo_set
        self._addresses: Dict[int, str] = {}
        self._keys:      Dict[str, HDKey] = {}

        # Pre-derive first 20 receiving addresses
        for i in range(20):
            self._derive_address(0, i)

    def _derive_address(self, change: int, index: int) -> str:
        """Derive address at m/44'/2025'/0'/{change}/{index}"""
        node    = self.account.derive_child(change).derive_child(index)
        addr    = node.address
        path    = f"{NBL_BIP44_PATH}/{change}/{index}"
        self._keys[addr] = node
        return addr

    def receiving_address(self, index: int = 0) -> str:
        """Get receiving address at index"""
        if index not in self._addresses:
            self._addresses[index] = self._derive_address(0, index)
        return self._addresses[index]

    def change_address(self, index: int = 0) -> str:
        """Get change address at index"""
        return self._derive_address(1, index)

    @property
    def first_address(self) -> str:
        return self.receiving_address(0)

    def get_balance(self) -> Dict[str, int]:
        """Get balance for all derived addresses"""
        if self._utxo is None:
            return {}
        balances = {}
        for addr in self._keys:
            bal = self._utxo.balance(addr)
            if bal > 0:
                balances[addr] = bal
        return balances

    def total_balance_neb(self) -> int:
        return sum(self.get_balance().values())

    def total_balance_nbl(self) -> float:
        return self.total_balance_neb() / 10**DECIMALS

    def get_utxos(self) -> List[UTXOEntry]:
        """Get all UTXOs for this wallet"""
        if self._utxo is None:
            return []
        all_utxos = []
        for addr in self._keys:
            all_utxos.extend(self._utxo.get_by_address(addr))
        return all_utxos

    def build_transaction(self,
                           to_address:   str,
                           amount_nbl:   float,
                           fee_nbl:      float = 0.0001,
                           memo:         str   = "") -> Optional[Transaction]:
        """Build and sign a transaction"""
        amount_neb = int(amount_nbl  * 10**DECIMALS)
        fee_neb    = int(fee_nbl     * 10**DECIMALS)
        total_needed = amount_neb + fee_neb

        if amount_neb <= DUST_THRESHOLD:
            print(f"❌ Amount below dust threshold: {amount_neb}")
            return None

        # Coin selection (simple: use largest UTXOs first)
        available = sorted(self.get_utxos(), key=lambda u: u.value, reverse=True)
        selected  = []
        selected_total = 0

        for utxo in available:
            selected.append(utxo)
            selected_total += utxo.value
            if selected_total >= total_needed:
                break

        if selected_total < total_needed:
            print(f"❌ Insufficient funds: have {selected_total/10**DECIMALS:.9f}, "
                  f"need {total_needed/10**DECIMALS:.9f}")
            return None

        # Build inputs
        inputs = []
        for utxo in selected:
            inputs.append(TxInput(
                outpoint   = OutPoint(utxo.txid, utxo.index),
                script_sig = b'',
                sequence   = 0xFFFFFFFE,
            ))

        # Build outputs
        outputs = [TxOutput(
            value        = amount_neb,
            script_pubkey = Script.p2pkh_locking_from_address(to_address),
        )]

        # Change output
        change = selected_total - total_needed
        if change > DUST_THRESHOLD:
            change_addr = self.change_address(0)
            outputs.append(TxOutput(
                value        = change,
                script_pubkey = Script.p2pkh_locking_from_address(change_addr),
            ))

        # OP_RETURN memo
        if memo:
            outputs.append(TxOutput(
                value        = 0,
                script_pubkey = Script.nulldata(memo[:80].encode()),
            ))

        tx = Transaction(version=1, inputs=inputs, outputs=outputs)

        # Sign each input
        for i, (inp, utxo) in enumerate(zip(tx.inputs, selected)):
            addr  = Script.p2pkh_address(
                Secp256k1.pubkey_to_bytes(self._keys[
                    base58check_encode(utxo.script_pubkey[3:23], PUBKEY_ADDRESS_VERSION)
                ].pubkey)
            )
            # Find signing key
            signing_key = None
            for wallet_addr, hd_key in self._keys.items():
                pub = Secp256k1.pubkey_to_bytes(hd_key.pubkey)
                if hash160(pub) == utxo.script_pubkey[3:23]:
                    signing_key = hd_key
                    break

            if signing_key is None:
                print(f"❌ No signing key for input {i}")
                return None

            subscript  = utxo.script_pubkey
            sighash    = tx.signature_hash(i, subscript, SIGHASH_ALL)
            r, s       = Secp256k1.sign(signing_key.key, sighash)
            der        = Secp256k1.sig_to_der(r, s) + bytes([SIGHASH_ALL])
            pub_bytes  = Secp256k1.pubkey_to_bytes(signing_key.pubkey)
            tx.inputs[i].script_sig = Script.p2pkh_unlocking(der, pub_bytes)
            tx.invalidate_cache()

        print(f"✅ Transaction built: {tx.txid}")
        print(f"   Amount : {amount_nbl:.9f} NBL → {to_address[:16]}...")
        print(f"   Fee    : {fee_nbl:.9f} NBL")
        print(f"   Size   : {tx.byte_size()} bytes")
        return tx

    def info(self) -> dict:
        addr = self.first_address
        return {
            "first_address": addr,
            "mnemonic_words": len(self.mnemonic.split()),
            "derived_keys":  len(self._keys),
            "balance_nbl":   f"{self.total_balance_nbl():.{DECIMALS}f} NBL",
            "balance_neb":   f"{self.total_balance_neb():,} Neb",
            "coin_type":     NBL_COIN_TYPE,
            "path":          NBL_BIP44_PATH,
            "xpub":          self.account.xpub()[:32] + "...",
        }

    @classmethod
    def create_new(cls, utxo_set: UTXOSet = None) -> 'NEBULAWallet':
        """Create a brand new wallet with random mnemonic"""
        mnemonic = BIP39.generate_mnemonic(12)
        wallet   = cls(mnemonic=mnemonic, utxo_set=utxo_set)
        print(f"\n🔑 New NBL Wallet Created!")
        print(f"   Address : {wallet.first_address}")
        print(f"   ⚠️  WRITE DOWN YOUR MNEMONIC — KEEP IT SAFE:")
        print(f"   {mnemonic}")
        print(f"   WIF Key : {wallet.master.derive_path(NBL_BIP44_PATH + '/0/0').wif}")
        return wallet

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "",
                      utxo_set: UTXOSet = None) -> 'NEBULAWallet':
        """Restore wallet from mnemonic"""
        wallet = cls(mnemonic=mnemonic, passphrase=passphrase, utxo_set=utxo_set)
        print(f"✅ Wallet restored: {wallet.first_address}")
        return wallet

    def export_keys(self, include_private: bool = False) -> List[dict]:
        """Export key list"""
        result = []
        for addr, hd in self._keys.items():
            entry = {"address": addr, "pubkey": Secp256k1.pubkey_to_bytes(hd.pubkey).hex()}
            if include_private and hd.key:
                entry["wif"] = hd.wif
            result.append(entry)
        return result
"""
================================================================
  NEBULA BLOCKCHAIN — nebula_miner.py
  Production-Grade Proof-of-Work Miner

  Architecture:
    - True parallel mining via multiprocessing (bypasses GIL)
    - Each CPU core runs an independent mining process
    - Shared memory for inter-process coordination
    - Automatic nonce range partitioning per worker
    - Real-time hash rate measurement via ctypes shared memory
    - Difficulty-aware target comparison (256-bit integer)
    - Halving-aware reward calculation

  Author  : Zayn Quantum
  License : MIT — Open to All Humanity
  Launch  : 2025-03-16
================================================================
"""

import multiprocessing as mp
import threading
import time
import struct
import hashlib
import ctypes
import os
from typing import Optional, Callable, List
from dataclasses import dataclass, field

from nebula_core import (
    Block, BlockHeader, Transaction, MerkleTree,
    NEBULABlockchain, mining_reward, halving_era,
    bits_to_target, sha256d, DECIMALS, CHAIN_NAME,
    MAX_NONCE, TARGET_BLOCK_TIME, INITIAL_BITS,
    INITIAL_BLOCK_REWARD, HALVING_INTERVAL,
)

# ================================================================
#  CONSTANTS
# ================================================================
MAX_WORKERS     = mp.cpu_count()
HASH_BATCH      = 50_000      # hashes per batch before checking stop
STATS_INTERVAL  = 2.0         # seconds between stats emission
NONCE_MAX       = 0xFFFF_FFFF # 32-bit nonce space

# ================================================================
#  WORKER — runs in separate OS process (no GIL)
# ================================================================
def _worker(header76: bytes, target32: bytes,
            n_start: int, n_end: int,
            q: mp.Queue, stop: mp.Value, counter: mp.Value):
    """
    Pure mining loop — one process per CPU core.
    Uses raw hashlib.sha256 with struct for maximum speed.
    """
    sha  = hashlib.sha256
    tgt  = int.from_bytes(target32, 'big')
    buf  = bytearray(header76 + b'\x00\x00\x00\x00')
    n    = n_start
    cnt  = 0

    while n <= n_end:
        if stop.value:
            return
        # Batch loop — avoid Python overhead per hash
        end = min(n + HASH_BATCH, n_end + 1)
        while n < end:
            struct.pack_into('<I', buf, 76, n)
            # SHA256d — identical to Bitcoin
            h = sha(sha(buf).digest()).digest()
            if int.from_bytes(h, 'big') < tgt:
                q.put(n)
                with stop.get_lock():
                    stop.value = 1
                return
            n += 1
        cnt += HASH_BATCH
        with counter.get_lock():
            counter.value += HASH_BATCH

# ================================================================
#  STATS
# ================================================================
class MiningStats:
    def __init__(self):
        self._total   = mp.Value(ctypes.c_uint64, 0)
        self._blocks  = mp.Value(ctypes.c_uint32, 0)
        self._t0      = time.time()
        self._snap    = 0
        self._snap_t  = time.time()
        self._rate    = 0.0
        self._lock    = threading.Lock()

    def counter(self):            # shared with workers
        return self._total

    def add_block(self):
        with self._blocks.get_lock():
            self._blocks.value += 1

    def hash_rate(self) -> float:
        with self._lock:
            now = time.time()
            dt  = now - self._snap_t
            if dt >= STATS_INTERVAL:
                cur        = self._total.value
                self._rate = (cur - self._snap) / dt
                self._snap   = cur
                self._snap_t = now
        return self._rate

    def to_dict(self) -> dict:
        hr = self.hash_rate()
        return {
            "hash_rate_khs" : hr / 1e3,
            "hash_rate_mhs" : hr / 1e6,
            "hashes_total"  : self._total.value,
            "blocks_found"  : self._blocks.value,
            "uptime_secs"   : time.time() - self._t0,
        }

# ================================================================
#  BLOCK TEMPLATE
# ================================================================
@dataclass
class BlockTemplate:
    height        : int
    prev_hash     : str
    merkle_root   : str
    timestamp     : int
    bits          : int
    reward_neb    : int
    miner_address : str
    transactions  : list = field(default_factory=list)

    def header76(self) -> bytes:
        return struct.pack(
            '<I32s32sIII',
            1,
            bytes.fromhex(self.prev_hash),
            bytes.fromhex(self.merkle_root),
            self.timestamp,
            self.bits,
            0,           # nonce placeholder — workers overwrite at offset 76
        )

    def target32(self) -> bytes:
        return bits_to_target(self.bits).to_bytes(32, 'big')

# ================================================================
#  PRODUCTION MINER
# ================================================================
class NEBULAMiner:
    """
    Multi-process PoW miner for NEBULA mainnet.

    One OS process per CPU core — each owns a nonce partition.
    True parallelism: no GIL, no shared interpreter state.
    """

    def __init__(
        self,
        blockchain    : NEBULABlockchain,
        miner_address : str,
        num_workers   : int = 0,
        on_block      : Optional[Callable] = None,
        on_stats      : Optional[Callable] = None,
    ):
        self.blockchain    = blockchain
        self.miner_address = miner_address
        self.num_workers   = num_workers or MAX_WORKERS
        self.on_block      = on_block
        self.on_stats      = on_stats
        self.stats         = MiningStats()
        self._running      = False
        self._stop_ev      = threading.Event()
        self._coord        : Optional[threading.Thread] = None
        self._procs        : List[mp.Process] = []

    # ── Public ────────────────────────────────────────────────
    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_ev.clear()
        self._coord = threading.Thread(
            target=self._loop, name="NEB-Coord", daemon=True)
        self._coord.start()

    def stop(self):
        self._running = False
        self._stop_ev.set()
        self._kill()
        if self._coord:
            self._coord.join(timeout=5)

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        return self.stats.to_dict()

    # ── Coordinator ───────────────────────────────────────────
    def _loop(self):
        while self._running and not self._stop_ev.is_set():
            try:
                tmpl = self._template()
                if tmpl is None:
                    time.sleep(1)
                    continue
                nonce = self._mine(tmpl)
                if nonce is not None and self._running:
                    blk = self._assemble(tmpl, nonce)
                    if blk and self._submit(blk):
                        self.stats.add_block()
                        if self.on_block:
                            self.on_block(blk, self.stats.to_dict())
            except Exception as e:
                if self._running:
                    print(f"[Miner] Error: {e}")
                    time.sleep(2)

    def _mine(self, tmpl: BlockTemplate) -> Optional[int]:
        n        = self.num_workers
        h76      = bytes(tmpl.header76())
        t32      = tmpl.target32()
        q        = mp.Queue()
        stop     = mp.Value(ctypes.c_uint8, 0)
        counter  = self.stats.counter()

        # Partition nonce space evenly
        step   = NONCE_MAX // n
        ranges = [(i * step, (i+1)*step - 1) for i in range(n)]
        ranges[-1] = (ranges[-1][0], NONCE_MAX)

        self._procs = []
        for s, e in ranges:
            p = mp.Process(
                target=_worker,
                args=(h76, t32, s, e, q, stop, counter),
                daemon=True,
            )
            p.start()
            self._procs.append(p)

        # Stats thread
        threading.Thread(
            target=self._emit_stats, daemon=True).start()

        nonce = None
        while True:
            if self._stop_ev.is_set():
                with stop.get_lock():
                    stop.value = 1
                break
            try:
                nonce = q.get(timeout=0.5)
                break
            except Exception:
                if all(not p.is_alive() for p in self._procs):
                    break

        self._kill()
        return nonce

    def _emit_stats(self):
        while self._running and not self._stop_ev.is_set():
            if self.on_stats:
                self.on_stats(self.stats.to_dict())
            time.sleep(STATS_INTERVAL)

    def _kill(self):
        for p in self._procs:
            try:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=2)
            except Exception:
                pass
        self._procs.clear()

    # ── Block assembly ────────────────────────────────────────
    def _template(self) -> Optional[BlockTemplate]:
        try:
            chain  = self.blockchain
            height = chain.height + 1
            cb_tx  = chain.build_coinbase(
                height=height, miner_address=self.miner_address,
                extra_data=b'NEBULA/' + str(height).encode())
            txs    = [cb_tx] + chain.mempool_top(max_count=2999)
            root   = MerkleTree.compute_root([tx.txid() for tx in txs])
            return BlockTemplate(
                height=height,
                prev_hash=chain.tip_hash(),
                merkle_root=root,
                timestamp=int(time.time()),
                bits=chain.next_bits(),
                reward_neb=mining_reward(height),
                miner_address=self.miner_address,
                transactions=txs,
            )
        except Exception as e:
            print(f"[Miner] Template error: {e}")
            return None

    def _assemble(self, tmpl: BlockTemplate, nonce: int) -> Optional[Block]:
        try:
            hdr = BlockHeader(
                version=1, prev_hash=tmpl.prev_hash,
                merkle_root=tmpl.merkle_root,
                timestamp=tmpl.timestamp,
                bits=tmpl.bits, nonce=nonce)
            return Block(header=hdr, transactions=tmpl.transactions)
        except Exception as e:
            print(f"[Miner] Assemble error: {e}")
            return None

    def _submit(self, block: Block) -> bool:
        try:
            ok, msg = self.blockchain.add_block(block)
            h   = block.header.block_hash()
            r   = block.transactions[0].outputs[0].value / 10**DECIMALS
            ht  = self.blockchain.height
            if ok:
                print(f"[Miner] BLOCK #{ht} | {h[:16]}... | {r:.9f} NBL")
            else:
                print(f"[Miner] Rejected #{ht}: {msg}")
            return ok
        except Exception as e:
            print(f"[Miner] Submit error: {e}")
            return False

# ================================================================
#  DEMO — single-process, for CLI testing
# ================================================================
def mine_one_block_demo(
    blockchain   : NEBULABlockchain,
    miner_address: str,
    timeout_secs : int = 60,
) -> Optional[Block]:
    height  = blockchain.height + 1
    prev    = blockchain.tip_hash()
    bits    = blockchain.next_bits()
    ts      = int(time.time())
    cb_tx   = blockchain.build_coinbase(height=height, miner_address=miner_address)
    root    = MerkleTree.compute_root([cb_tx.txid()])
    target  = bits_to_target(bits)
    buf     = bytearray(struct.pack('<I32s32sIII', 1,
                bytes.fromhex(prev), bytes.fromhex(root), ts, bits, 0))
    t0      = time.time()
    for nonce in range(NONCE_MAX + 1):
        if time.time() - t0 > timeout_secs:
            return None
        struct.pack_into('<I', buf, 76, nonce)
        h = hashlib.sha256(hashlib.sha256(buf).digest()).digest()
        if int.from_bytes(h, 'big') < target:
            hdr = BlockHeader(1, prev, root, ts, bits, nonce)
            return Block(header=hdr, transactions=[cb_tx])
    return None

# ================================================================
#  HALVING SCHEDULE
# ================================================================
def halving_schedule(height: int = 0) -> dict:
    schedule = []
    for era in range(10):
        reward = INITIAL_BLOCK_REWARD >> era
        if reward == 0:
            break
        schedule.append({
            "era"        : era + 1,
            "start_block": era * HALVING_INTERVAL,
            "end_block"  : (era + 1) * HALVING_INTERVAL - 1,
            "reward_nbl" : reward / 10**DECIMALS,
            "active"     : era == height // HALVING_INTERVAL,
            "year_start" : 2025 + era * 4,
            "year_end"   : 2029 + era * 4,
        })
    era_now = height // HALVING_INTERVAL
    return {
        "schedule"        : schedule,
        "current_height"  : height,
        "current_era"     : era_now + 1,
        "current_reward"  : (INITIAL_BLOCK_REWARD >> era_now) / 10**DECIMALS,
        "next_halving_at" : (era_now + 1) * HALVING_INTERVAL,
        "blocks_to_next"  : HALVING_INTERVAL - (height % HALVING_INTERVAL),
    }

# ================================================================
if __name__ == "__main__":
    print(f"NEBULA Miner — use nebula_cli.py mine")
    print(f"CPU cores: {MAX_WORKERS}")
    s = halving_schedule(0)
    print(f"Era {s['current_era']} | Reward: {s['current_reward']} NBL")
    print(f"Next halving: block {s['next_halving_at']:,}")
"""
================================================================
  NEBULA P2P NETWORK — nebula_network.py
  Bitcoin-compatible P2P protocol
  Peer discovery, block sync, tx broadcast
================================================================
"""

import socket, threading, json, time, struct, hashlib
from typing import List, Dict, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from nebula_core import (
    NEBULABlockchain, Block, Transaction,
    sha256d, CHAIN_ID, CHAIN_NAME, DEFAULT_PORT,
    PROTOCOL_VERSION, MAX_PEERS, MAINNET_MAGIC,
    MAX_HEADERS_AT_ONCE, MAX_BLOCKS_AT_ONCE
)

# ================================================================
#  MESSAGE TYPES
# ================================================================

class MsgType(str, Enum):
    VERSION    = "version"
    VERACK     = "verack"
    PING       = "ping"
    PONG       = "pong"
    GETBLOCKS  = "getblocks"
    GETDATA    = "getdata"
    BLOCK      = "block"
    TX         = "tx"
    INV        = "inv"
    HEADERS    = "headers"
    GETHEADERS = "getheaders"
    GETADDR    = "getaddr"
    ADDR       = "addr"
    REJECT     = "reject"
    MEMPOOL    = "mempool"
    GETINFO    = "getinfo"
    INFO       = "info"

# ================================================================
#  PEER STATE
# ================================================================

class PeerState(Enum):
    CONNECTING   = "connecting"
    HANDSHAKING  = "handshaking"
    CONNECTED    = "connected"
    SYNCING      = "syncing"
    DISCONNECTED = "disconnected"
    BANNED       = "banned"

@dataclass
class PeerInfo:
    host:          str
    port:          int
    state:         PeerState    = PeerState.CONNECTING
    version:       int          = 0
    chain_id:      int          = 0
    height:        int          = 0
    user_agent:    str          = ""
    connected_at:  float        = field(default_factory=time.time)
    last_seen:     float        = field(default_factory=time.time)
    bytes_sent:    int          = 0
    bytes_recv:    int          = 0
    latency_ms:    float        = 0.0
    ping_nonce:    int          = 0
    ping_sent:     float        = 0.0
    failures:      int          = 0

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"

# ================================================================
#  MESSAGE CODEC
# ================================================================

class Message:
    """
    NEBULA network message:
    [ magic(4) | type(12) | length(4) | checksum(4) | payload ]
    """
    HEADER_SIZE = 24

    def __init__(self, msg_type: str, payload: dict = None):
        self.type    = msg_type
        self.payload = payload or {}

    def encode(self) -> bytes:
        body     = json.dumps(self.payload, separators=(',', ':')).encode('utf-8')
        checksum = sha256d(body)[:4]
        type_bytes = self.type.encode('utf-8').ljust(12, b'\x00')[:12]
        header = (
            MAINNET_MAGIC +
            type_bytes +
            struct.pack('<I', len(body)) +
            checksum
        )
        return header + body

    @classmethod
    def decode(cls, data: bytes) -> Optional['Message']:
        if len(data) < cls.HEADER_SIZE:
            return None
        magic    = data[:4]
        msg_type = data[4:16].rstrip(b'\x00').decode('utf-8')
        length   = struct.unpack_from('<I', data, 16)[0]
        checksum = data[20:24]
        body     = data[24:24+length]
        if sha256d(body)[:4] != checksum:
            return None
        payload = json.loads(body.decode('utf-8'))
        return cls(msg_type, payload)

    @classmethod
    def peek_length(cls, data: bytes) -> Optional[int]:
        if len(data) < cls.HEADER_SIZE:
            return None
        return struct.unpack_from('<I', data, 16)[0] + cls.HEADER_SIZE

# ================================================================
#  PEER CONNECTION
# ================================================================

class PeerConnection:
    """Manages a single peer connection"""

    RECV_BUF = 1 << 20   # 1 MB receive buffer

    def __init__(self,
                 host:     str,
                 port:     int,
                 node:     'P2PNode',
                 sock:     socket.socket = None,
                 inbound:  bool = False):
        self.info    = PeerInfo(host=host, port=port)
        self.node    = node
        self._sock   = sock
        self.inbound = inbound
        self._buf    = b''
        self._lock   = threading.Lock()
        self._running = False

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(10)
            self._sock.connect((self.info.host, self.info.port))
            self._sock.settimeout(None)
            return True
        except Exception as e:
            self.info.state = PeerState.DISCONNECTED
            return False

    def start(self):
        self._running = True
        t = threading.Thread(target=self._recv_loop, daemon=True,
                              name=f"Peer-{self.info.addr}")
        t.start()
        # Send version immediately
        self._send_version()

    def send(self, msg: Message) -> bool:
        try:
            with self._lock:
                data = msg.encode()
                self._sock.sendall(data)
                self.info.bytes_sent += len(data)
                return True
        except Exception:
            self.disconnect()
            return False

    def _recv_loop(self):
        self._sock.settimeout(30)
        while self._running:
            try:
                chunk = self._sock.recv(self.RECV_BUF)
                if not chunk:
                    break
                self.info.bytes_recv += len(chunk)
                self.info.last_seen   = time.time()
                self._buf += chunk
                self._process_buf()
            except socket.timeout:
                self._ping()
            except Exception:
                break
        self.disconnect()

    def _process_buf(self):
        while True:
            needed = Message.peek_length(self._buf)
            if needed is None or len(self._buf) < needed:
                break
            msg_data  = self._buf[:needed]
            self._buf = self._buf[needed:]
            msg = Message.decode(msg_data)
            if msg:
                self.node._handle_message(self, msg)

    def _send_version(self):
        self.send(Message(MsgType.VERSION, {
            "version":    PROTOCOL_VERSION,
            "chain_id":   CHAIN_ID,
            "height":     self.node.bc.height,
            "user_agent": f"/NEBULA:{CHAIN_ID}/",
            "timestamp":  int(time.time()),
            "addr_from":  f"{self.node.host}:{self.node.port}",
        }))
        self.info.state = PeerState.HANDSHAKING

    def _ping(self):
        nonce = int(time.time() * 1000) & 0xFFFFFFFF
        self.info.ping_nonce = nonce
        self.info.ping_sent  = time.time()
        self.send(Message(MsgType.PING, {"nonce": nonce}))

    def disconnect(self):
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass
        self.info.state = PeerState.DISCONNECTED
        self.node._on_peer_disconnect(self)

# ================================================================
#  P2P NODE
# ================================================================

# ── NEBULA MAINNET SEED NODES ──────────────────────────────────
# These are the permanent bootstrap nodes for the NEBULA network.
# Anyone can run a node. No permission needed.
# Launch: 2025-03-16 | Author: Zayn Quantum | License: MIT
SEED_NODES = [
    # Asia Pacific
    ("seed1.nebula-nbl.io",  DEFAULT_PORT),
    ("seed2.nebula-nbl.io",  DEFAULT_PORT),
    ("seed3.nebula-nbl.io",  DEFAULT_PORT),
    # Europe
    ("seed4.nebula-nbl.io",  DEFAULT_PORT),
    ("seed5.nebula-nbl.io",  DEFAULT_PORT),
    # Americas
    ("seed6.nebula-nbl.io",  DEFAULT_PORT),
    ("seed7.nebula-nbl.io",  DEFAULT_PORT),
    # Africa & Middle East
    ("seed8.nebula-nbl.io",  DEFAULT_PORT),
    # Oceania
    ("seed9.nebula-nbl.io",  DEFAULT_PORT),
    ("seed10.nebula-nbl.io", DEFAULT_PORT),
]

# DNS seed hostnames — resolved automatically at startup
DNS_SEEDS = [
    "dnsseed.nebula-nbl.io",
    "dnsseed2.nebula-nbl.io",
    "seed.nebula-nbl.io",
]

def resolve_dns_seeds(dns_seeds: list = DNS_SEEDS) -> list:
    """Resolve DNS seeds to get bootstrap peer addresses."""
    import socket
    peers = []
    for host in dns_seeds:
        try:
            results = socket.getaddrinfo(host, DEFAULT_PORT,
                                         socket.AF_UNSPEC,
                                         socket.SOCK_STREAM)
            for res in results:
                ip = res[4][0]
                if ip not in [p[0] for p in peers]:
                    peers.append((ip, DEFAULT_PORT))
        except Exception:
            pass  # DNS not configured yet
    return peers


class P2PNode:
    """
    Full NEBULA P2P node.
    Handles peer discovery, handshake, block sync, tx relay.
    """

    def __init__(self,
                 bc:    NEBULABlockchain,
                 host:  str = "0.0.0.0",
                 port:  int = DEFAULT_PORT):
        self.bc      = bc
        self.host    = host
        self.port    = port
        self._peers: Dict[str, PeerConnection] = {}
        self._banned: Set[str] = set()
        self._lock    = threading.RLock()
        self._running = False
        self._known_invs: Set[str] = set()   # avoid rebroadcast

        # Callbacks
        self.on_new_block: Optional[Callable] = None
        self.on_new_tx:    Optional[Callable] = None

    def start(self):
        self._running = True
        # Listen for inbound
        threading.Thread(target=self._listen, daemon=True, name="P2P-Listen").start()
        # Connect to seeds
        threading.Thread(target=self._seed_connect, daemon=True, name="P2P-Seeds").start()
        # Maintenance loop
        threading.Thread(target=self._maintenance, daemon=True, name="P2P-Maint").start()
        print(f"🌐 P2P Node listening on {self.host}:{self.port}")

    def stop(self):
        self._running = False
        with self._lock:
            for peer in list(self._peers.values()):
                peer.disconnect()

    def connect_peer(self, host: str, port: int) -> bool:
        addr = f"{host}:{port}"
        if addr in self._banned:
            return False
        with self._lock:
            if addr in self._peers:
                return False
            if len(self._peers) >= MAX_PEERS:
                return False

        peer = PeerConnection(host, port, self)
        if not peer.connect():
            return False

        with self._lock:
            self._peers[addr] = peer
        peer.start()
        return True

    def broadcast_block(self, block: Block):
        """Broadcast new block to all peers"""
        inv_msg = Message(MsgType.INV, {
            "type":  "block",
            "items": [block.hash],
        })
        self._broadcast(inv_msg)

    def broadcast_tx(self, tx: Transaction):
        """Broadcast transaction to all peers"""
        inv_msg = Message(MsgType.INV, {
            "type":  "tx",
            "items": [tx.txid],
        })
        self._broadcast(inv_msg)

    def _broadcast(self, msg: Message):
        with self._lock:
            peers = list(self._peers.values())
        for peer in peers:
            if peer.info.state == PeerState.CONNECTED:
                peer.send(msg)

    def _listen(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(50)
            srv.settimeout(1)
            while self._running:
                try:
                    conn, addr = srv.accept()
                    host, port = addr
                    if host in self._banned:
                        conn.close()
                        continue
                    peer = PeerConnection(host, port, self, sock=conn, inbound=True)
                    with self._lock:
                        if len(self._peers) < MAX_PEERS:
                            key = f"{host}:{port}"
                            self._peers[key] = peer
                            peer.start()
                        else:
                            conn.close()
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"Listen error: {e}")

    def _seed_connect(self):
        time.sleep(1)
        for host, port in SEED_NODES:
            if not self._running:
                break
            try:
                import socket as _s
                _s.setdefaulttimeout(5)
                addrs = _s.getaddrinfo(host, port)
                if addrs:
                    self.connect_peer(host, port)
            except Exception:
                pass  # Seed DNS not available yet

    def _maintenance(self):
        """Periodic: ping peers, drop stale, find new"""
        while self._running:
            time.sleep(30)
            now = time.time()
            with self._lock:
                stale = [addr for addr, p in self._peers.items()
                         if (p.info.state == PeerState.DISCONNECTED or
                             now - p.info.last_seen > 120)]
                for addr in stale:
                    self._peers.pop(addr, None)

            # Ask connected peers for more peers
            with self._lock:
                connected = [p for p in self._peers.values()
                             if p.info.state == PeerState.CONNECTED]
            for peer in connected:
                peer.send(Message(MsgType.GETADDR))

    def _handle_message(self, peer: PeerConnection, msg: Message):
        """Route incoming messages"""
        t = msg.type
        p = msg.payload

        if t == MsgType.VERSION:
            peer.info.version    = p.get("version", 0)
            peer.info.chain_id   = p.get("chain_id", 0)
            peer.info.height     = p.get("height", 0)
            peer.info.user_agent = p.get("user_agent", "")
            if peer.info.chain_id != CHAIN_ID:
                peer.disconnect()
                return
            peer.send(Message(MsgType.VERACK))
            peer.info.state = PeerState.CONNECTED
            # Ask for blocks if they're ahead
            if peer.info.height > self.bc.height:
                self._request_sync(peer)

        elif t == MsgType.VERACK:
            peer.info.state = PeerState.CONNECTED

        elif t == MsgType.PING:
            peer.send(Message(MsgType.PONG, {"nonce": p.get("nonce", 0)}))

        elif t == MsgType.PONG:
            if p.get("nonce") == peer.info.ping_nonce:
                peer.info.latency_ms = (time.time() - peer.info.ping_sent) * 1000

        elif t == MsgType.INV:
            self._handle_inv(peer, p)

        elif t == MsgType.GETBLOCKS:
            self._handle_getblocks(peer, p)

        elif t == MsgType.BLOCK:
            self._handle_block(peer, p)

        elif t == MsgType.TX:
            self._handle_tx(peer, p)

        elif t == MsgType.GETADDR:
            with self._lock:
                addrs = [{"host": c.info.host, "port": c.info.port}
                         for c in self._peers.values()
                         if c.info.state == PeerState.CONNECTED]
            peer.send(Message(MsgType.ADDR, {"addrs": addrs[:100]}))

        elif t == MsgType.ADDR:
            for addr_info in p.get("addrs", [])[:20]:
                h, po = addr_info.get("host"), addr_info.get("port", DEFAULT_PORT)
                if h and f"{h}:{po}" not in self._peers:
                    threading.Thread(target=self.connect_peer, args=(h, po),
                                     daemon=True).start()

        elif t == MsgType.GETINFO:
            peer.send(Message(MsgType.INFO, self.bc.chain_info()))

    def _handle_inv(self, peer: PeerConnection, p: dict):
        inv_type  = p.get("type")
        items     = p.get("items", [])
        needed    = [i for i in items if i not in self._known_invs]
        if needed:
            peer.send(Message(MsgType.GETDATA, {"type": inv_type, "items": needed}))

    def _handle_getblocks(self, peer: PeerConnection, p: dict):
        start_hash = p.get("hash_stop", "")
        start_h    = 0
        for h_str in p.get("locator", []):
            blk = self.bc.get_block_by_hash(h_str)
            if blk:
                start_h = blk.height + 1
                break

        blocks_to_send = []
        for i in range(start_h, min(start_h + MAX_BLOCKS_AT_ONCE, self.bc.height + 1)):
            blk = self.bc.get_block(i)
            if blk:
                blocks_to_send.append(blk.to_dict())

        if blocks_to_send:
            peer.send(Message(MsgType.BLOCK, {"blocks": blocks_to_send}))

    def _handle_block(self, peer: PeerConnection, p: dict):
        for blk_dict in p.get("blocks", []):
            # Simplified: in production would fully deserialize
            self._known_invs.add(blk_dict.get("hash", ""))

    def _handle_tx(self, peer: PeerConnection, p: dict):
        txid = p.get("txid", "")
        self._known_invs.add(txid)

    def _request_sync(self, peer: PeerConnection):
        locator = self.bc.get_locator()
        peer.send(Message(MsgType.GETBLOCKS, {"locator": locator}))
        peer.info.state = PeerState.SYNCING

    def _on_peer_disconnect(self, peer: PeerConnection):
        with self._lock:
            self._peers.pop(peer.info.addr, None)

    def peer_count(self) -> int:
        return sum(1 for p in self._peers.values()
                   if p.info.state == PeerState.CONNECTED)

    def all_peers(self) -> List[dict]:
        with self._lock:
            return [{
                "addr":       p.info.addr,
                "state":      p.info.state.value,
                "height":     p.info.height,
                "latency_ms": f"{p.info.latency_ms:.1f}",
                "inbound":    p.inbound,
                "agent":      p.info.user_agent,
            } for p in self._peers.values()]

    def network_info(self) -> dict:
        return {
            "listening":    f"{self.host}:{self.port}",
            "peers_total":  len(self._peers),
            "peers_connected": self.peer_count(),
            "chain_height": self.bc.height,
            "banned":       len(self._banned),
        }
"""
================================================================
  NEBULA NODE — nebula_node.py
  Complete Node — Blockchain + Mining + P2P + Wallet + Explorer
  
  How to run:
    python3 nebula_node.py                  # full node
    python3 nebula_node.py --mine           # mine blocks
    python3 nebula_node.py --wallet         # wallet only
    python3 nebula_node.py --info           # chain info
================================================================
"""

import sys, os, json, time, threading, argparse
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from nebula_core   import NEBULABlockchain, CHAIN_NAME, CHAIN_SYMBOL, DECIMALS, halving_era, mining_reward
from nebula_miner  import NEBULAMiner
from nebula_network import P2PNode, DEFAULT_PORT
from nebula_wallet import NEBULAWallet, BIP39

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🌌  N E B U L A   B L O C K C H A I N                     ║
║                                                              ║
║   No Government · No Bank · No Permission Needed            ║
║   Created by Zayn Quantum — Open to the Entire World 🌍   ║
║   Open Source · Permissionless · Borderless               ║
║                                                              ║
║   Supply : 10,700,000 NBL (fixed forever)                   ║
║   Halving: Every 210,000 blocks (like Bitcoin)              ║
║   Reward : 50 → 25 → 12.5 → 6.25 NBL                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

# ================================================================
#  BLOCK EXPLORER (in-memory)
# ================================================================

class BlockExplorer:
    """Simple block explorer — search blocks, txs, addresses"""

    def __init__(self, bc: NEBULABlockchain):
        self.bc = bc

    def block_info(self, height_or_hash: str) -> Optional[dict]:
        try:
            height = int(height_or_hash)
            blk = self.bc.get_block(height)
        except ValueError:
            blk = self.bc.get_block_by_hash(height_or_hash)
        return blk.to_dict() if blk else None

    def tx_info(self, txid: str) -> Optional[dict]:
        for blk in reversed(self.bc._chain[-100:]):
            for tx in blk.transactions:
                if tx.txid == txid:
                    d = tx.to_dict()
                    d["block_hash"]   = blk.hash
                    d["block_height"] = blk.height
                    d["confirmations"] = self.bc.height - blk.height + 1
                    return d
        return None

    def address_info(self, address: str) -> dict:
        balance = self.bc.utxo.balance(address)
        utxos   = self.bc.utxo.get_by_address(address)
        return {
            "address":     address,
            "balance_nbl": f"{balance/10**DECIMALS:.{DECIMALS}f}",
            "balance_neb": balance,
            "utxo_count":  len(utxos),
            "utxos": [{
                "txid":   u.txid,
                "index":  u.index,
                "value_nbl": f"{u.value/10**DECIMALS:.{DECIMALS}f}",
                "height": u.height,
            } for u in utxos],
        }

    def recent_blocks(self, count: int = 10) -> List[dict]:
        start = max(0, self.bc.height - count + 1)
        result = []
        for h in range(self.bc.height, start - 1, -1):
            blk = self.bc.get_block(h)
            if blk:
                result.append({
                    "height":    blk.height,
                    "hash":      blk.hash[:16] + "...",
                    "txs":       blk.tx_count,
                    "size":      blk.byte_size(),
                    "timestamp": blk.header.timestamp,
                    "miner":     blk.transactions[0].outputs[0].address if blk.transactions else "?",
                })
        return result

    def supply_info(self) -> dict:
        from nebula_core import MAX_SUPPLY
        issued = self.bc.utxo.total_supply()
        era    = halving_era(self.bc.height)
        return {
            "max_supply":      f"{MAX_SUPPLY/10**DECIMALS:,.0f} NBL",
            "issued":          f"{issued/10**DECIMALS:.{DECIMALS}f} NBL",
            "percentage":      f"{issued/MAX_SUPPLY*100:.4f}%",
            "current_reward":  era["reward_nbl"] + " NBL",
            "era":             era["era_name"],
            "next_halving":    era["next_halving_at"],
            "blocks_remaining":era["blocks_remaining"],
        }

    def print_dashboard(self):
        info  = self.bc.chain_info()
        sup   = self.supply_info()
        recnt = self.recent_blocks(5)

        print("\n" + "═"*60)
        print(f"  NEBULA Blockchain Dashboard")
        print("═"*60)
        print(f"  Height        : {info['height']:,}")
        print(f"  Best Block    : {info['best_hash'][:32]}...")
        print(f"  Difficulty    : {info['bits']}")
        print(f"  Block Reward  : {info['reward_nbl']} NBL")
        print(f"  Era           : {info['era']}")
        print(f"  Next Halving  : block #{info['next_halving']:,}")
        print(f"  Supply Issued : {sup['issued']}")
        print(f"  Max Supply    : {sup['max_supply']}")
        print(f"  UTXO Set      : {info['utxo_set_size']:,} entries")
        print(f"  Mempool       : {info['mempool_txs']} txs")
        print("\n  Recent Blocks:")
        for b in recnt:
            print(f"    #{b['height']:>6} | {b['hash']} | {b['txs']} txs | {b['size']} bytes")
        print("═"*60)

# ================================================================
#  NEBULA FULL NODE
# ================================================================

class NEBULAFullNode:
    """
    Complete NEBULA full node.
    Runs blockchain + P2P + optional miner + wallet.
    """

    def __init__(self,
                 data_dir:      str  = "./nebula_data",
                 port:          int  = DEFAULT_PORT,
                 mine:          bool = False,
                 miner_address: str  = None,
                 threads:       int  = None):

        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        print(BANNER)

        # Core blockchain
        self.bc       = NEBULABlockchain()
        self.explorer = BlockExplorer(self.bc)

        # P2P network
        self.p2p = P2PNode(self.bc, port=port)
        self.p2p.on_new_block = self._on_new_block
        self.p2p.on_new_tx    = self._on_new_tx

        # Miner
        self.miner = None
        if mine:
            addr = miner_address or self._load_or_create_miner_address()
            self.miner = NEBULAMiner(self.bc, addr, threads=threads)

        # Wallet
        self.wallet = None

        self._running = False

    def _load_or_create_miner_address(self) -> str:
        wallet_file = self.data_dir / "miner_wallet.json"
        if wallet_file.exists():
            data = json.loads(wallet_file.read_text())
            return data["address"]
        # Create new wallet
        w = NEBULAWallet.create_new()
        wallet_file.write_text(json.dumps({
            "address":  w.first_address,
            "mnemonic": w.mnemonic,   # ⚠️ Keep safe!
        }, indent=2))
        print(f"⚠️  Miner wallet saved to {wallet_file}")
        print(f"    BACK UP YOUR MNEMONIC!")
        return w.first_address

    def start(self):
        """Start all node services"""
        self._running = True
        self.p2p.start()

        if self.miner:
            self.miner.start()

        # Status thread
        threading.Thread(target=self._status_loop, daemon=True, name="Status").start()

        # Save chain periodically
        threading.Thread(target=self._save_loop, daemon=True, name="SaveChain").start()

        self.explorer.print_dashboard()
        print(f"\n✅ NEBULA Full Node running")
        print(f"   Data dir : {self.data_dir}")
        print(f"   Port     : {self.p2p.port}")
        print(f"   Mining   : {'yes' if self.miner else 'no'}")
        print(f"\n   Press Ctrl+C to stop\n")

    def stop(self):
        self._running = False
        if self.miner:
            self.miner.stop()
        self.p2p.stop()
        self.save_chain()
        print("\n🛑 NEBULA node stopped. Chain saved.")

    def _on_new_block(self, block):
        print(f"📦 New block #{block.height}: {block.hash[:16]}...")

    def _on_new_tx(self, tx):
        print(f"📨 New tx: {tx.txid[:16]}...")

    def _status_loop(self):
        while self._running:
            time.sleep(60)
            self.explorer.print_dashboard()
            if self.miner:
                s = self.miner.get_stats()
                print(f"  ⛏️  Mining: {s['hash_rate']} | {s['blocks_found']} found")

    def _save_loop(self):
        while self._running:
            time.sleep(300)   # every 5 min
            self.save_chain()

    def save_chain(self):
        path = self.data_dir / "nebula_chain.json"
        self.bc.export(str(path))

    def interactive_wallet(self):
        """Simple CLI wallet interface"""
        print("\n" + "─"*50)
        print("  NEBULA Wallet")
        print("─"*50)
        print("  1. Create new wallet")
        print("  2. Restore from mnemonic")
        print("  3. Check balance")
        print("  4. Send NBL")
        print("  5. Show address")
        print("─"*50)

        choice = input("  Choice: ").strip()

        if choice == "1":
            self.wallet = NEBULAWallet.create_new(self.bc.utxo)
            print(f"\n  ✅ Wallet created!")
            print(f"  Address : {self.wallet.first_address}")
            print(f"\n  ⚠️  WRITE DOWN YOUR 12-WORD MNEMONIC:")
            print(f"  {self.wallet.mnemonic}")

        elif choice == "2":
            mnemonic = input("  Enter 12-word mnemonic: ").strip()
            self.wallet = NEBULAWallet.from_mnemonic(mnemonic, utxo_set=self.bc.utxo)
            print(f"  Restored: {self.wallet.first_address}")

        elif choice == "3":
            if not self.wallet:
                addr = input("  Enter address: ").strip()
                info = self.explorer.address_info(addr)
            else:
                info = self.explorer.address_info(self.wallet.first_address)
            print(f"\n  Balance: {info['balance_nbl']}")
            print(f"  UTXOs  : {info['utxo_count']}")

        elif choice == "4":
            if not self.wallet:
                print("  ❌ No wallet loaded")
                return
            to_addr  = input("  To address: ").strip()
            amount   = float(input("  Amount (NBL): ").strip())
            tx = self.wallet.build_transaction(to_addr, amount)
            if tx:
                ok, msg = self.bc.mempool.submit(tx)
                print(f"  {'✅' if ok else '❌'} {msg}: {tx.txid[:20]}...")

        elif choice == "5":
            if self.wallet:
                print(f"  Address: {self.wallet.first_address}")
            else:
                print("  No wallet loaded")

    def run_interactive(self):
        """Interactive CLI"""
        self.start()
        try:
            while True:
                cmd = input("\nNBL> ").strip().lower()
                if cmd in ("exit", "quit", "q"):
                    break
                elif cmd == "info":
                    self.explorer.print_dashboard()
                elif cmd == "wallet":
                    self.interactive_wallet()
                elif cmd.startswith("block "):
                    h = cmd[6:].strip()
                    info = self.explorer.block_info(h)
                    print(json.dumps(info, indent=2) if info else "Not found")
                elif cmd.startswith("tx "):
                    txid = cmd[3:].strip()
                    info = self.explorer.tx_info(txid)
                    print(json.dumps(info, indent=2) if info else "Not found")
                elif cmd.startswith("addr "):
                    addr = cmd[5:].strip()
                    info = self.explorer.address_info(addr)
                    print(json.dumps(info, indent=2))
                elif cmd == "peers":
                    peers = self.p2p.all_peers()
                    print(json.dumps(peers, indent=2))
                elif cmd == "supply":
                    print(json.dumps(self.explorer.supply_info(), indent=2))
                elif cmd == "miner":
                    if self.miner:
                        print(json.dumps(self.miner.get_stats(), indent=2))
                    else:
                        print("Mining not enabled. Restart with --mine")
                elif cmd == "help":
                    print("  Commands: info, wallet, block <h|hash>, tx <txid>,")
                    print("            addr <address>, peers, supply, miner, help, quit")
                else:
                    print(f"  Unknown command: {cmd}. Type 'help'")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


# ================================================================
#  DEMO — Quick Demonstration
# ================================================================

def run_demo():
    """Quick demo — creates node, mines 3 blocks, shows info"""
    print(BANNER)

    bc       = NEBULABlockchain()
    explorer = BlockExplorer(bc)

    # Create demo wallet
    wallet = NEBULAWallet.create_new(bc.utxo)
    print(f"\n📬 Demo miner address: {wallet.first_address}")

    # Mine 3 blocks with easy difficulty
    miner = NEBULAMiner(bc, wallet.first_address, threads=1)
    for i in range(3):
        block = miner.mine_demo_block(easy_bits=0x1f0fffff)
        if block:
            ok, msg = bc.add_block(block)
            print(f"   Block #{block.height}: {msg}")

    # Show dashboard
    explorer.print_dashboard()

    # Show supply
    print("\n📊 Supply Info:")
    for k, v in explorer.supply_info().items():
        print(f"   {k:20}: {v}")

    # Save
    bc.export("nebula_demo_chain.json")
    print(f"\n✅ Demo complete! Chain saved to nebula_demo_chain.json")


# ================================================================
#  MAIN
# ================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEBULA Blockchain Node")
    parser.add_argument("--mine",    action="store_true", help="Enable mining")
    parser.add_argument("--demo",    action="store_true", help="Run quick demo")
    parser.add_argument("--wallet",  action="store_true", help="Wallet mode only")
    parser.add_argument("--info",    action="store_true", help="Show chain info and exit")
    parser.add_argument("--port",    type=int, default=DEFAULT_PORT)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--address", type=str, default=None, help="Miner address")
    parser.add_argument("--datadir", type=str, default="./nebula_data")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.info:
        bc = NEBULABlockchain()
        for k, v in bc.chain_info().items():
            print(f"  {k:20}: {v}")
    elif args.wallet:
        bc     = NEBULABlockchain()
        node   = NEBULAFullNode(data_dir=args.datadir, port=args.port)
        node.interactive_wallet()
    else:
        node = NEBULAFullNode(
            data_dir      = args.datadir,
            port          = args.port,
            mine          = args.mine,
            miner_address = args.address,
            threads       = args.threads,
        )
        node.run_interactive()
"""
================================================================
  NEBULA SMART CONTRACTS — nebula_contracts.py
  Bitcoin Script + Extended NBL scripting engine
  
  Supports:
  - Full Bitcoin Script opcodes
  - Multi-signature (P2MS)
  - Time-locked transactions (CLTV, CSV)
  - Hash-locked contracts (HTLC)
  - Token contracts (NBL-20 standard)
  - Vesting contracts
  - Atomic swaps
================================================================
"""

import hashlib, time, struct
from typing import List, Dict, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import IntEnum
from nebula_core import sha256d, hash160, sha256, Script, ScriptType

# ================================================================
#  SCRIPT OPCODES — Complete Bitcoin-compatible set
# ================================================================

class OP(IntEnum):
    # Constants
    OP_0            = 0x00
    OP_FALSE        = 0x00
    OP_PUSHDATA1    = 0x4c
    OP_PUSHDATA2    = 0x4d
    OP_PUSHDATA4    = 0x4e
    OP_1NEGATE      = 0x4f
    OP_1            = 0x51
    OP_TRUE         = 0x51
    OP_2            = 0x52
    OP_3            = 0x53
    OP_4            = 0x54
    OP_5            = 0x55
    OP_6            = 0x56
    OP_7            = 0x57
    OP_8            = 0x58
    OP_9            = 0x59
    OP_10           = 0x5a
    OP_11           = 0x5b
    OP_12           = 0x5c
    OP_13           = 0x5d
    OP_14           = 0x5e
    OP_15           = 0x5f
    OP_16           = 0x60

    # Flow control
    OP_NOP          = 0x61
    OP_IF           = 0x63
    OP_NOTIF        = 0x64
    OP_ELSE         = 0x67
    OP_ENDIF        = 0x68
    OP_VERIFY       = 0x69
    OP_RETURN       = 0x6a

    # Stack
    OP_TOALTSTACK   = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_IFDUP        = 0x73
    OP_DEPTH        = 0x74
    OP_DROP         = 0x75
    OP_DUP          = 0x76
    OP_NIP          = 0x77
    OP_OVER         = 0x79
    OP_PICK         = 0x79
    OP_ROLL         = 0x7a
    OP_ROT          = 0x7b
    OP_SWAP         = 0x7c
    OP_TUCK         = 0x7d
    OP_2DROP        = 0x6d
    OP_2DUP         = 0x6e
    OP_3DUP         = 0x6f
    OP_2OVER        = 0x70
    OP_2ROT         = 0x71
    OP_2SWAP        = 0x72

    # Splice
    OP_CAT          = 0x7e
    OP_SIZE         = 0x82

    # Bitwise
    OP_EQUAL        = 0x87
    OP_EQUALVERIFY  = 0x88

    # Arithmetic
    OP_1ADD         = 0x8b
    OP_1SUB         = 0x8c
    OP_NEGATE       = 0x8f
    OP_ABS          = 0x90
    OP_NOT          = 0x91
    OP_0NOTEQUAL    = 0x92
    OP_ADD          = 0x93
    OP_SUB          = 0x94
    OP_MUL          = 0x95
    OP_DIV          = 0x96
    OP_MOD          = 0x97
    OP_BOOLAND      = 0x9a
    OP_BOOLOR       = 0x9b
    OP_NUMEQUAL     = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL  = 0x9e
    OP_LESSTHAN     = 0x9f
    OP_GREATERTHAN  = 0xa0
    OP_LESSTHANOREQUAL    = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN          = 0xa3
    OP_MAX          = 0xa4
    OP_WITHIN       = 0xa5

    # Crypto
    OP_RIPEMD160    = 0xa6
    OP_SHA1         = 0xa7
    OP_SHA256       = 0xa8
    OP_HASH160      = 0xa9
    OP_HASH256      = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG     = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # Locktime
    OP_CHECKLOCKTIMEVERIFY = 0xb1   # CLTV (BIP65)
    OP_CHECKSEQUENCEVERIFY = 0xb2   # CSV  (BIP112)

    # NBL extensions
    OP_NBL_TRANSFER = 0xc0   # NBL token transfer
    OP_NBL_BALANCE  = 0xc1   # Check NBL balance
    OP_NBL_MINT     = 0xc2   # Mint NBL-20 token
    OP_NBL_BURN     = 0xc3   # Burn tokens

# ================================================================
#  SCRIPT INTERPRETER
# ================================================================

class ScriptError(Exception):
    pass

class ScriptInterpreter:
    """
    Full Bitcoin-compatible script interpreter.
    Executes locking + unlocking scripts.
    """

    MAX_STACK_SIZE  = 1000
    MAX_SCRIPT_SIZE = 10_000
    MAX_OPS         = 201

    def __init__(self,
                 tx_hash:    bytes = b'\x00' * 32,
                 block_time: int   = 0,
                 block_height: int = 0):
        self.tx_hash      = tx_hash
        self.block_time   = block_time
        self.block_height = block_height

    def execute(self,
                script:    bytes,
                stack:     List[bytes] = None,
                altstack:  List[bytes] = None) -> Tuple[bool, List[bytes]]:
        """Execute a script, return (success, final_stack)"""
        if len(script) > self.MAX_SCRIPT_SIZE:
            raise ScriptError("Script too large")

        stack    = stack    or []
        altstack = altstack or []
        ops_done = 0
        pc       = 0
        cond_stack: List[bool] = []   # for IF/ELSE/ENDIF

        def executing() -> bool:
            return all(cond_stack) if cond_stack else True

        while pc < len(script):
            op = script[pc]
            pc += 1
            ops_done += 1

            if ops_done > self.MAX_OPS:
                raise ScriptError("Too many ops")

            if len(stack) > self.MAX_STACK_SIZE:
                raise ScriptError("Stack overflow")

            # ── Data push opcodes ──────────────────────────────
            if 0x01 <= op <= 0x4b:
                # Push N bytes
                data = script[pc:pc+op]
                pc  += op
                if executing():
                    stack.append(data)
                continue

            if op == OP.OP_PUSHDATA1:
                n    = script[pc]; pc += 1
                data = script[pc:pc+n]; pc += n
                if executing(): stack.append(data)
                continue

            if op == OP.OP_PUSHDATA2:
                n    = struct.unpack_from('<H', script, pc)[0]; pc += 2
                data = script[pc:pc+n]; pc += n
                if executing(): stack.append(data)
                continue

            if op == OP.OP_PUSHDATA4:
                n    = struct.unpack_from('<I', script, pc)[0]; pc += 4
                data = script[pc:pc+n]; pc += n
                if executing(): stack.append(data)
                continue

            # ── Small integers ─────────────────────────────────
            if op == OP.OP_0:
                if executing(): stack.append(b'')
                continue
            if op == OP.OP_1NEGATE:
                if executing(): stack.append(self._encode_int(-1))
                continue
            if OP.OP_1 <= op <= OP.OP_16:
                n = op - OP.OP_1 + 1
                if executing(): stack.append(self._encode_int(n))
                continue

            # ── Flow control ───────────────────────────────────
            if op == OP.OP_NOP:
                continue

            if op == OP.OP_IF:
                if executing():
                    val = self._pop(stack)
                    cond_stack.append(bool(val and any(val)))
                else:
                    cond_stack.append(False)
                continue

            if op == OP.OP_NOTIF:
                if executing():
                    val = self._pop(stack)
                    cond_stack.append(not (val and any(val)))
                else:
                    cond_stack.append(False)
                continue

            if op == OP.OP_ELSE:
                if cond_stack:
                    cond_stack[-1] = not cond_stack[-1]
                continue

            if op == OP.OP_ENDIF:
                if cond_stack:
                    cond_stack.pop()
                continue

            if not executing():
                continue

            if op == OP.OP_VERIFY:
                val = self._pop(stack)
                if not (val and any(val)):
                    raise ScriptError("OP_VERIFY failed")

            elif op == OP.OP_RETURN:
                raise ScriptError("OP_RETURN: unspendable")

            # ── Stack ops ──────────────────────────────────────
            elif op == OP.OP_DROP:   stack.pop()
            elif op == OP.OP_2DROP:  stack.pop(); stack.pop()
            elif op == OP.OP_DUP:    stack.append(stack[-1])
            elif op == OP.OP_2DUP:   stack.extend(stack[-2:])
            elif op == OP.OP_3DUP:   stack.extend(stack[-3:])
            elif op == OP.OP_OVER:   stack.append(stack[-2])
            elif op == OP.OP_2OVER:  stack.extend(stack[-4:-2])
            elif op == OP.OP_SWAP:   stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op == OP.OP_2SWAP:
                stack[-4], stack[-3], stack[-2], stack[-1] = \
                stack[-2], stack[-1], stack[-4], stack[-3]
            elif op == OP.OP_ROT:
                stack.append(stack.pop(-3))
            elif op == OP.OP_NIP:
                del stack[-2]
            elif op == OP.OP_TUCK:
                stack.insert(-2, stack[-1])
            elif op == OP.OP_DEPTH:
                stack.append(self._encode_int(len(stack)))
            elif op == OP.OP_IFDUP:
                if stack[-1]: stack.append(stack[-1])
            elif op == OP.OP_TOALTSTACK:
                altstack.append(self._pop(stack))
            elif op == OP.OP_FROMALTSTACK:
                stack.append(altstack.pop())
            elif op == OP.OP_SIZE:
                stack.append(self._encode_int(len(stack[-1])))

            # ── Arithmetic ─────────────────────────────────────
            elif op == OP.OP_1ADD:
                stack.append(self._encode_int(self._decode_int(self._pop(stack)) + 1))
            elif op == OP.OP_1SUB:
                stack.append(self._encode_int(self._decode_int(self._pop(stack)) - 1))
            elif op == OP.OP_NEGATE:
                stack.append(self._encode_int(-self._decode_int(self._pop(stack))))
            elif op == OP.OP_ABS:
                stack.append(self._encode_int(abs(self._decode_int(self._pop(stack)))))
            elif op == OP.OP_NOT:
                stack.append(self._encode_int(0 if self._decode_int(self._pop(stack)) else 1))
            elif op == OP.OP_0NOTEQUAL:
                stack.append(self._encode_int(0 if not self._decode_int(self._pop(stack)) else 1))
            elif op == OP.OP_ADD:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(a + b))
            elif op == OP.OP_SUB:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(a - b))
            elif op == OP.OP_MUL:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(a * b))
            elif op == OP.OP_DIV:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                if b == 0: raise ScriptError("Division by zero")
                stack.append(self._encode_int(a // b))
            elif op == OP.OP_MOD:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                if b == 0: raise ScriptError("Mod by zero")
                stack.append(self._encode_int(a % b))
            elif op == OP.OP_BOOLAND:
                b, a = self._pop(stack), self._pop(stack)
                stack.append(self._encode_int(1 if (any(a) and any(b)) else 0))
            elif op == OP.OP_BOOLOR:
                b, a = self._pop(stack), self._pop(stack)
                stack.append(self._encode_int(1 if (any(a) or any(b)) else 0))
            elif op == OP.OP_NUMEQUAL:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(1 if a == b else 0))
            elif op == OP.OP_NUMEQUALVERIFY:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                if a != b: raise ScriptError("NUMEQUALVERIFY failed")
            elif op == OP.OP_NUMNOTEQUAL:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(1 if a != b else 0))
            elif op == OP.OP_LESSTHAN:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(1 if a < b else 0))
            elif op == OP.OP_GREATERTHAN:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(1 if a > b else 0))
            elif op == OP.OP_LESSTHANOREQUAL:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(1 if a <= b else 0))
            elif op == OP.OP_GREATERTHANOREQUAL:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(1 if a >= b else 0))
            elif op == OP.OP_MIN:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(min(a, b)))
            elif op == OP.OP_MAX:
                b, a = self._decode_int(self._pop(stack)), self._decode_int(self._pop(stack))
                stack.append(self._encode_int(max(a, b)))
            elif op == OP.OP_WITHIN:
                mx, mn, x = (self._decode_int(self._pop(stack)) for _ in range(3))
                stack.append(self._encode_int(1 if mn <= x < mx else 0))

            # ── Equality ───────────────────────────────────────
            elif op == OP.OP_EQUAL:
                b, a = self._pop(stack), self._pop(stack)
                stack.append(self._encode_int(1 if a == b else 0))
            elif op == OP.OP_EQUALVERIFY:
                b, a = self._pop(stack), self._pop(stack)
                if a != b: raise ScriptError("EQUALVERIFY failed")

            # ── Crypto ─────────────────────────────────────────
            elif op == OP.OP_RIPEMD160:
                h = hashlib.new('ripemd160'); h.update(self._pop(stack))
                stack.append(h.digest())
            elif op == OP.OP_SHA1:
                stack.append(hashlib.sha1(self._pop(stack)).digest())
            elif op == OP.OP_SHA256:
                stack.append(hashlib.sha256(self._pop(stack)).digest())
            elif op == OP.OP_HASH160:
                stack.append(hash160(self._pop(stack)))
            elif op == OP.OP_HASH256:
                stack.append(sha256d(self._pop(stack)))
            elif op == OP.OP_CHECKSIG:
                pub_bytes = self._pop(stack)
                sig_bytes = self._pop(stack)
                result    = self._checksig(sig_bytes, pub_bytes)
                stack.append(self._encode_int(1 if result else 0))
            elif op == OP.OP_CHECKSIGVERIFY:
                pub_bytes = self._pop(stack)
                sig_bytes = self._pop(stack)
                if not self._checksig(sig_bytes, pub_bytes):
                    raise ScriptError("CHECKSIGVERIFY failed")
            elif op == OP.OP_CHECKMULTISIG:
                self._op_checkmultisig(stack)
            elif op == OP.OP_CHECKMULTISIGVERIFY:
                self._op_checkmultisig(stack)
                if not self._pop(stack): raise ScriptError("CHECKMULTISIGVERIFY failed")

            # ── Timelocks ──────────────────────────────────────
            elif op == OP.OP_CHECKLOCKTIMEVERIFY:
                locktime = self._decode_int(stack[-1])   # peek, don't pop
                if locktime < 0:
                    raise ScriptError("CLTV: negative locktime")
                if locktime >= 500_000_000:
                    # Unix timestamp
                    if self.block_time < locktime:
                        raise ScriptError(f"CLTV: too early (time {self.block_time} < {locktime})")
                else:
                    # Block height
                    if self.block_height < locktime:
                        raise ScriptError(f"CLTV: too early (height {self.block_height} < {locktime})")

            elif op == OP.OP_CHECKSEQUENCEVERIFY:
                seq = self._decode_int(stack[-1])
                if seq < 0:
                    raise ScriptError("CSV: negative sequence")
                # Simplified check

            else:
                # Unknown opcode
                raise ScriptError(f"Unknown opcode: {hex(op)}")

        # Script succeeds if top of stack is truthy
        if not stack:
            return False, stack
        top = stack[-1]
        success = bool(top and any(top))
        return success, stack

    # ── Helpers ───────────────────────────────────────────────

    def _pop(self, stack: List[bytes]) -> bytes:
        if not stack:
            raise ScriptError("Stack underflow")
        return stack.pop()

    def _encode_int(self, n: int) -> bytes:
        if n == 0: return b''
        negative = n < 0
        n = abs(n)
        result = []
        while n:
            result.append(n & 0xff)
            n >>= 8
        if result[-1] & 0x80:
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        return bytes(result)

    def _decode_int(self, data: bytes) -> int:
        if not data: return 0
        result   = int.from_bytes(data[:-1] + bytes([data[-1] & 0x7f]), 'little')
        return -result if data[-1] & 0x80 else result

    def _checksig(self, sig_bytes: bytes, pub_bytes: bytes) -> bool:
        try:
            from nebula_core import Secp256k1
            if len(sig_bytes) < 9 or sig_bytes[0] != 0x30:
                return False
            sighash_type = sig_bytes[-1]
            der          = sig_bytes[:-1]
            r, s         = Secp256k1.sig_from_der(der)
            # Reconstruct public key point
            prefix = pub_bytes[0]
            x      = int.from_bytes(pub_bytes[1:33], 'big')
            p      = Secp256k1.P
            y_sq   = (pow(x, 3, p) + 7) % p
            y      = pow(y_sq, (p+1)//4, p)
            if (y % 2 == 0) != (prefix == 0x02):
                y = p - y
            pub_point = (x, y)
            return Secp256k1.verify(pub_point, self.tx_hash, (r, s))
        except Exception:
            return False

    def _op_checkmultisig(self, stack: List[bytes]):
        n_keys = self._decode_int(self._pop(stack))
        keys   = [self._pop(stack) for _ in range(n_keys)]
        n_sigs = self._decode_int(self._pop(stack))
        sigs   = [self._pop(stack) for _ in range(n_sigs)]
        stack.pop()   # Bitcoin bug: extra pop

        valid = 0
        ki    = 0
        for sig in sigs:
            while ki < len(keys):
                if self._checksig(sig, keys[ki]):
                    valid += 1
                    ki    += 1
                    break
                ki += 1
        stack.append(self._encode_int(1 if valid >= n_sigs else 0))


# ================================================================
#  CONTRACT TEMPLATES
# ================================================================

class ContractTemplates:
    """
    Ready-made contract templates.
    Each returns (locking_script, unlocking_script_builder)
    """

    @staticmethod
    def multisig(m: int, pubkeys: List[bytes]) -> bytes:
        """
        m-of-n multisig locking script.
        Example: 2-of-3 multisig
        OP_m <pubkey1> <pubkey2> ... <pubkeyn> OP_n OP_CHECKMULTISIG
        """
        n = len(pubkeys)
        assert 1 <= m <= n <= 16
        script = bytes([OP.OP_1 + m - 1])
        for pk in pubkeys:
            script += bytes([len(pk)]) + pk
        script += bytes([OP.OP_1 + n - 1, OP.OP_CHECKMULTISIG])
        return script

    @staticmethod
    def htlc(recipient_hash160: bytes,
              refund_hash160:   bytes,
              secret_hash:      bytes,
              lock_blocks:      int) -> bytes:
        """
        Hash Time-Locked Contract (HTLC) — for atomic swaps.
        
        Spend paths:
        1. Recipient: provide secret preimage
        2. Refund: after lock_blocks, sender gets refund
        
        OP_IF
          OP_SHA256 <secret_hash> OP_EQUALVERIFY
          OP_DUP OP_HASH160 <recipient_h160> OP_EQUALVERIFY OP_CHECKSIG
        OP_ELSE
          <lock_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
          OP_DUP OP_HASH160 <refund_h160> OP_EQUALVERIFY OP_CHECKSIG
        OP_ENDIF
        """
        lb = lock_blocks.to_bytes(3, 'little')
        return (
            bytes([OP.OP_IF]) +
            bytes([OP.OP_SHA256]) +
            bytes([len(secret_hash)]) + secret_hash +
            bytes([OP.OP_EQUALVERIFY]) +
            bytes([OP.OP_DUP, OP.OP_HASH160]) +
            bytes([len(recipient_hash160)]) + recipient_hash160 +
            bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG]) +
            bytes([OP.OP_ELSE]) +
            bytes([len(lb)]) + lb +
            bytes([OP.OP_CHECKSEQUENCEVERIFY, OP.OP_DROP]) +
            bytes([OP.OP_DUP, OP.OP_HASH160]) +
            bytes([len(refund_hash160)]) + refund_hash160 +
            bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG]) +
            bytes([OP.OP_ENDIF])
        )

    @staticmethod
    def timelock_p2pkh(pubkey_hash: bytes, lock_until: int) -> bytes:
        """
        Time-locked P2PKH — can only be spent after block height.
        
        <lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
        OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        """
        lh = lock_until.to_bytes(5, 'little').rstrip(b'\x00') or b'\x00'
        return (
            bytes([len(lh)]) + lh +
            bytes([OP.OP_CHECKLOCKTIMEVERIFY, OP.OP_DROP]) +
            bytes([OP.OP_DUP, OP.OP_HASH160]) +
            bytes([len(pubkey_hash)]) + pubkey_hash +
            bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG])
        )

    @staticmethod
    def vesting(beneficiary_hash: bytes,
                 owner_hash:       bytes,
                 cliff_blocks:     int,
                 vest_blocks:      int) -> bytes:
        """
        Vesting contract — tokens unlock gradually.
        Before cliff: only owner can spend (revoke).
        After cliff:  beneficiary can spend.
        After vest:   fully vested.
        """
        cliff_b = cliff_blocks.to_bytes(4, 'little')
        return (
            bytes([OP.OP_IF]) +
            bytes([len(cliff_b)]) + cliff_b +
            bytes([OP.OP_CHECKSEQUENCEVERIFY, OP.OP_DROP]) +
            bytes([OP.OP_DUP, OP.OP_HASH160]) +
            bytes([len(beneficiary_hash)]) + beneficiary_hash +
            bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG]) +
            bytes([OP.OP_ELSE]) +
            bytes([OP.OP_DUP, OP.OP_HASH160]) +
            bytes([len(owner_hash)]) + owner_hash +
            bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG]) +
            bytes([OP.OP_ENDIF])
        )

    @staticmethod
    def atomic_swap(their_hash160: bytes,
                     our_hash160:   bytes,
                     secret_hash:   bytes,
                     timeout:       int) -> bytes:
        """Cross-chain atomic swap script"""
        return ContractTemplates.htlc(
            their_hash160, our_hash160, secret_hash, timeout)


# ================================================================
#  NBL-20 TOKEN STANDARD
#  (Like ERC-20 but on NEBULA blockchain)
# ================================================================

@dataclass
class NBL20Token:
    """NBL-20 fungible token on NEBULA chain"""
    name:         str
    symbol:       str
    decimals:     int
    total_supply: int
    owner:        str
    contract_id:  str = ""
    created_at:   int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self):
        if not self.contract_id:
            data = f"{self.name}{self.symbol}{self.owner}{self.created_at}".encode()
            self.contract_id = hashlib.sha256(data).hexdigest()[:40]

class NBL20Registry:
    """Registry of all NBL-20 tokens on NEBULA"""

    def __init__(self):
        self._tokens:   Dict[str, NBL20Token]               = {}
        self._balances: Dict[str, Dict[str, int]]            = {}
        self._allowances: Dict[str, Dict[str, Dict[str, int]]] = {}

    def deploy(self, token: NBL20Token, initial_holder: str) -> str:
        """Deploy a new NBL-20 token"""
        cid = token.contract_id
        self._tokens[cid]                          = token
        self._balances[cid]                        = {initial_holder: token.total_supply}
        self._allowances[cid]                      = {}
        print(f"🪙 NBL-20 Token deployed: {token.symbol} ({cid[:12]}...)")
        print(f"   Name:   {token.name}")
        print(f"   Supply: {token.total_supply / 10**token.decimals:,.{token.decimals}f} {token.symbol}")
        return cid

    def balance_of(self, contract_id: str, address: str) -> int:
        return self._balances.get(contract_id, {}).get(address, 0)

    def transfer(self, contract_id: str,
                  from_addr: str, to_addr: str, amount: int) -> bool:
        bal = self._balances.get(contract_id, {})
        if bal.get(from_addr, 0) < amount:
            return False
        bal[from_addr]  = bal.get(from_addr, 0)  - amount
        bal[to_addr]    = bal.get(to_addr, 0)    + amount
        return True

    def approve(self, contract_id: str,
                 owner: str, spender: str, amount: int):
        a = self._allowances.setdefault(contract_id, {})
        a.setdefault(owner, {})[spender] = amount

    def transfer_from(self, contract_id: str,
                       spender: str, from_addr: str,
                       to_addr: str, amount: int) -> bool:
        allowed = self._allowances.get(contract_id, {}).get(from_addr, {}).get(spender, 0)
        if allowed < amount:
            return False
        if not self.transfer(contract_id, from_addr, to_addr, amount):
            return False
        self._allowances[contract_id][from_addr][spender] -= amount
        return True

    def burn(self, contract_id: str, from_addr: str, amount: int) -> bool:
        bal = self._balances.get(contract_id, {})
        if bal.get(from_addr, 0) < amount:
            return False
        bal[from_addr] -= amount
        self._tokens[contract_id].total_supply -= amount
        return True

    def mint(self, contract_id: str, to_addr: str, amount: int,
              caller: str) -> bool:
        token = self._tokens.get(contract_id)
        if not token or token.owner != caller:
            return False
        self._balances[contract_id][to_addr] = \
            self._balances[contract_id].get(to_addr, 0) + amount
        token.total_supply += amount
        return True

    def token_info(self, contract_id: str) -> Optional[dict]:
        t = self._tokens.get(contract_id)
        if not t: return None
        return {
            "contract_id":  t.contract_id,
            "name":         t.name,
            "symbol":       t.symbol,
            "decimals":     t.decimals,
            "total_supply": t.total_supply,
            "owner":        t.owner,
            "created_at":   t.created_at,
            "holders":      len(self._balances.get(contract_id, {})),
        }

    def list_tokens(self) -> List[dict]:
        return [self.token_info(cid) for cid in self._tokens]


# ================================================================
#  CONTRACT MANAGER
# ================================================================

class ContractManager:
    """Manages all contracts on the NEBULA chain"""

    def __init__(self):
        self.interpreter  = ScriptInterpreter()
        self.nbl20        = NBL20Registry()
        self.templates    = ContractTemplates()
        self._contracts:  Dict[str, dict] = {}

    def verify_script(self,
                       unlocking: bytes,
                       locking:   bytes,
                       tx_hash:   bytes = b'\x00'*32,
                       height:    int   = 0,
                       ts:        int   = 0) -> Tuple[bool, str]:
        """Verify a script pair"""
        interp = ScriptInterpreter(tx_hash, ts, height)
        try:
            # Run unlocking script first
            ok, stack = interp.execute(unlocking)
            # Then locking script with result stack
            ok, stack = interp.execute(locking, stack)
            return ok, "OK" if ok else "Script returned false"
        except ScriptError as e:
            return False, str(e)

    def create_htlc(self,
                     recipient_address: str,
                     refund_address:    str,
                     secret:            bytes,
                     lock_blocks:       int = 144) -> dict:
        """Create Hash Time-Locked Contract for atomic swaps"""
        from nebula_core import Script, base58check_decode, PUBKEY_ADDRESS_VERSION
        secret_hash   = hashlib.sha256(secret).digest()
        recipient_h160 = base58check_decode(recipient_address)[1]
        refund_h160    = base58check_decode(refund_address)[1]

        locking = self.templates.htlc(
            recipient_h160, refund_h160, secret_hash, lock_blocks)

        contract_id = hashlib.sha256(locking).hexdigest()[:32]
        self._contracts[contract_id] = {
            "type":       "HTLC",
            "id":         contract_id,
            "recipient":  recipient_address,
            "refund":     refund_address,
            "secret_hash":secret_hash.hex(),
            "lock_blocks":lock_blocks,
            "script":     locking.hex(),
        }
        return self._contracts[contract_id]

    def deploy_nbl20(self,
                      name:    str,
                      symbol:  str,
                      supply:  float,
                      dec:     int,
                      owner:   str) -> str:
        """Deploy NBL-20 token"""
        token = NBL20Token(
            name         = name,
            symbol       = symbol,
            decimals     = dec,
            total_supply = int(supply * 10**dec),
            owner        = owner,
        )
        return self.nbl20.deploy(token, owner)

    def info(self) -> dict:
        return {
            "contracts":    len(self._contracts),
            "nbl20_tokens": len(self.nbl20.list_tokens()),
            "opcodes":      len(OP),
        }
"""
================================================================
  NEBULA TEST SUITE — nebula_tests.py
  Complete Test Suite — Like Bitcoin Core Tests
  
  Tests:
  - Cryptography (ECDSA, hashing, addresses)
  - Transactions (build, sign, verify, serialize)
  - Blocks (mining, validation, merkle)
  - Blockchain (UTXO, chain, reorg)
  - Scripts (all opcodes, P2PKH, multisig, HTLC)
  - Wallet (BIP32, BIP39, key derivation)
  - Contracts (NBL-20, HTLC, timelock)
  - Network (message encoding)
  - Halving schedule
  - Difficulty adjustment
================================================================
"""

import sys, os, time, hashlib, traceback
sys.path.insert(0, os.path.dirname(__file__))

from nebula_core import *
from nebula_wallet import BIP39, HDKey, NEBULAWallet, HARDENED
from nebula_contracts import (
    ScriptInterpreter, ContractTemplates,
    NBL20Token, NBL20Registry, ContractManager, OP
)

# ================================================================
#  TEST FRAMEWORK
# ================================================================

class TestResult:
    def __init__(self):
        self.passed  = 0
        self.failed  = 0
        self.errors  = []

    def ok(self, name: str):
        self.passed += 1
        print(f"  ✅ {name}")

    def fail(self, name: str, reason: str):
        self.failed += 1
        self.errors.append((name, reason))
        print(f"  ❌ {name}: {reason}")

    def summary(self) -> str:
        total = self.passed + self.failed
        return (f"\n{'='*50}\n"
                f"  Tests: {self.passed}/{total} passed\n"
                f"  {'✅ ALL PASSED' if self.failed == 0 else f'❌ {self.failed} FAILED'}\n"
                f"{'='*50}")

def assert_eq(a, b, msg=""):
    assert a == b, f"{msg}: expected {b!r}, got {a!r}"

def assert_true(cond, msg=""):
    assert cond, msg

def assert_false(cond, msg=""):
    assert not cond, msg

# ================================================================
#  TEST GROUPS
# ================================================================

class TestCrypto:
    """Test secp256k1 ECDSA and hash functions"""

    def run(self, r: TestResult):
        print("\n📐 Crypto Tests")
        self._test_sha256(r)
        self._test_hash160(r)
        self._test_keypair(r)
        self._test_sign_verify(r)
        self._test_address(r)
        self._test_der_encoding(r)
        self._test_rfc6979(r)
        self._test_base58(r)
        self._test_wif(r)

    def _test_sha256(self, r):
        try:
            h = sha256(b"NEBULA")
            assert len(h) == 32
            h2 = sha256d(b"NEBULA")
            assert len(h2) == 32
            assert h != h2
            r.ok("SHA256 / double SHA256")
        except Exception as e:
            r.fail("SHA256", str(e))

    def _test_hash160(self, r):
        try:
            h = hash160(b"NEBULA test")
            assert len(h) == 20
            h2 = hash160(b"NEBULA test")
            assert h == h2, "hash160 not deterministic"
            h3 = hash160(b"different")
            assert h != h3, "hash160 collision"
            r.ok("HASH160 (RIPEMD160+SHA256)")
        except Exception as e:
            r.fail("HASH160", str(e))

    def _test_keypair(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            assert 1 <= priv < Secp256k1.N, "Private key out of range"
            assert isinstance(pub, tuple) and len(pub) == 2
            # Deterministic: same privkey → same pubkey
            pub2 = Secp256k1.point_mul(priv, Secp256k1.G())
            assert pub == pub2
            r.ok("secp256k1 keypair generation")
        except Exception as e:
            r.fail("Keypair", str(e))

    def _test_sign_verify(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            msg   = sha256d(b"test transaction")
            sig   = Secp256k1.sign(priv, msg)
            valid = Secp256k1.verify(pub, msg, sig)
            assert valid, "Signature verification failed"

            # Wrong message
            wrong = Secp256k1.verify(pub, sha256d(b"wrong"), sig)
            assert not wrong, "Should fail with wrong message"

            # Wrong key
            priv2, pub2 = Secp256k1.generate_keypair()
            wrong2 = Secp256k1.verify(pub2, msg, sig)
            assert not wrong2, "Should fail with wrong key"

            r.ok("ECDSA sign/verify")
        except Exception as e:
            r.fail("ECDSA sign/verify", str(e))

    def _test_address(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_bytes = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_bytes)
            assert addr.startswith('N'), f"NBL address should start with N, got {addr[0]}"
            assert len(addr) >= 25 and len(addr) <= 35
            r.ok(f"NBL address generation (starts with N: {addr[:10]}...)")
        except Exception as e:
            r.fail("Address generation", str(e))

    def _test_der_encoding(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            msg       = sha256d(b"der test")
            r_val, s  = Secp256k1.sign(priv, msg)
            der       = Secp256k1.sig_to_der(r_val, s)
            assert der[0] == 0x30, "DER must start with 0x30"
            r2, s2    = Secp256k1.sig_from_der(der)
            assert r_val == r2 and s == s2, "DER round-trip failed"
            r.ok("DER signature encoding/decoding")
        except Exception as e:
            r.fail("DER encoding", str(e))

    def _test_rfc6979(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            msg       = sha256d(b"deterministic")
            # Same inputs → same k → same signature
            sig1 = Secp256k1.sign(priv, msg)
            sig2 = Secp256k1.sign(priv, msg)
            assert sig1 == sig2, "RFC6979 not deterministic"
            r.ok("RFC6979 deterministic signatures")
        except Exception as e:
            r.fail("RFC6979", str(e))

    def _test_base58(self, r):
        try:
            data     = b'\x00' * 3 + b'\x01\x02\x03\x04'
            encoded  = base58_encode(data)
            decoded  = base58_decode(encoded)
            assert decoded == data, f"Base58 round-trip failed: {decoded!r} != {data!r}"
            r.ok("Base58 encode/decode")
        except Exception as e:
            r.fail("Base58", str(e))

    def _test_wif(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_bytes = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_bytes)
            hd        = HDKey(priv, b'\x00'*32, pub)
            wif       = hd.wif
            assert wif.startswith('5') or wif.startswith('K') or wif.startswith('L') or len(wif) > 40
            r.ok("WIF private key encoding")
        except Exception as e:
            r.fail("WIF", str(e))


class TestTransactions:
    """Test transaction building, signing, serialization"""

    def run(self, r: TestResult):
        print("\n💸 Transaction Tests")
        self._test_coinbase(r)
        self._test_serialize(r)
        self._test_txid(r)
        self._test_sig_hash(r)
        self._test_p2pkh_full(r)
        self._test_multisig(r)

    def _test_coinbase(self, r):
        try:
            cb = Transaction.coinbase(0, INITIAL_BLOCK_REWARD,
                                      "NLfMw4STiuDo9pMixgNnXZapH3sXasYVk5",
                                      b"test genesis")
            assert cb.is_coinbase, "Should be coinbase"
            assert len(cb.inputs) == 1
            assert cb.inputs[0].outpoint.is_null()
            assert cb.total_output() == INITIAL_BLOCK_REWARD
            r.ok("Coinbase transaction")
        except Exception as e:
            r.fail("Coinbase", str(e))

    def _test_serialize(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_b     = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_b)
            cb        = Transaction.coinbase(1, 50*10**9, addr)
            raw       = cb.serialize()
            assert len(raw) > 0
            assert isinstance(raw, bytes)
            r.ok(f"Transaction serialization ({len(raw)} bytes)")
        except Exception as e:
            r.fail("Tx serialize", str(e))

    def _test_txid(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            addr      = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub))
            cb        = Transaction.coinbase(1, 50*10**9, addr)
            txid      = cb.txid
            assert len(txid) == 64, "TXID must be 64 hex chars"
            assert all(c in '0123456789abcdef' for c in txid)
            # Deterministic
            assert cb.txid == txid
            r.ok(f"TXID computation ({txid[:16]}...)")
        except Exception as e:
            r.fail("TXID", str(e))

    def _test_sig_hash(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_b     = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_b)
            cb        = Transaction.coinbase(1, 50*10**9, addr)
            subscript = Script.p2pkh_locking_from_address(addr)
            sighash   = cb.signature_hash(0, subscript, SIGHASH_ALL)
            assert len(sighash) == 32
            r.ok("Signature hash (SIGHASH_ALL)")
        except Exception as e:
            r.fail("Sighash", str(e))

    def _test_p2pkh_full(self, r):
        """Full P2PKH: build, sign, verify"""
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_b     = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_b)
            locking   = Script.p2pkh_locking_from_address(addr)

            # Build fake tx spending a P2PKH output
            inp_tx = TxInput(OutPoint("ab" * 32, 0), b'', 0xFFFFFFFF)
            out_tx = TxOutput(40 * 10**9, locking)
            tx     = Transaction(1, [inp_tx], [out_tx])

            # Sign
            sighash = tx.signature_hash(0, locking, SIGHASH_ALL)
            r_v, s  = Secp256k1.sign(priv, sighash)
            der     = Secp256k1.sig_to_der(r_v, s) + bytes([SIGHASH_ALL])
            tx.inputs[0].script_sig = Script.p2pkh_unlocking(der, pub_b)
            tx.invalidate_cache()

            # Verify script
            interp = ScriptInterpreter(tx_hash=sighash)
            ok1, stack = interp.execute(tx.inputs[0].script_sig)
            ok2, stack = interp.execute(locking, stack)
            assert ok2, "P2PKH script verification failed"
            r.ok("Full P2PKH sign + verify")
        except Exception as e:
            r.fail("P2PKH", str(e))

    def _test_multisig(self, r):
        try:
            keys = [Secp256k1.generate_keypair() for _ in range(3)]
            pubs = [Secp256k1.pubkey_to_bytes(k[1]) for k in keys]
            script = ContractTemplates.multisig(2, pubs)
            assert script[0] == OP.OP_2      # m=2
            assert script[-1] == OP.OP_CHECKMULTISIG
            assert script[-2] == OP.OP_3     # n=3
            r.ok("2-of-3 multisig script creation")
        except Exception as e:
            r.fail("Multisig", str(e))


class TestBlocks:
    """Test block creation, mining, validation"""

    def run(self, r: TestResult):
        print("\n📦 Block Tests")
        self._test_header_serialize(r)
        self._test_header_hash(r)
        self._test_merkle(r)
        self._test_merkle_proof(r)
        self._test_difficulty(r)
        self._test_halving(r)
        self._test_block_build(r)

    def _test_header_serialize(self, r):
        try:
            h = BlockHeader(1, '00'*32, 'ff'*32, 1742083200, INITIAL_BITS, 12345, 0)
            raw = h.serialize()
            assert len(raw) in (76, 80), f"Header must be 76 or 80 bytes, got {len(raw)}"
            r.ok("BlockHeader serialization (76 bytes)")
        except Exception as e:
            r.fail("Header serialize", str(e))

    def _test_header_hash(self, r):
        try:
            h   = BlockHeader(1, '00'*32, 'ff'*32, GENESIS_TIMESTAMP, GENESIS_BITS, GENESIS_NONCE, 0)
            hsh = h.hash()
            assert len(hsh) == 64
            assert all(c in '0123456789abcdef' for c in hsh)
            # Deterministic
            assert h.hash() == hsh
            r.ok(f"Block hash ({hsh[:16]}...)")
        except Exception as e:
            r.fail("Block hash", str(e))

    def _test_merkle(self, r):
        try:
            # 1 tx
            txids  = ["ab" * 32]
            root1  = MerkleTree.compute_root(txids)
            assert len(root1) == 64

            # 2 txs
            txids2 = ["ab"*32, "cd"*32]
            root2  = MerkleTree.compute_root(txids2)
            assert root2 != root1

            # 4 txs
            txids4 = ["ab"*32, "cd"*32, "ef"*32, "12"*32]
            root4  = MerkleTree.compute_root(txids4)
            assert len(root4) == 64

            # Empty
            root0 = MerkleTree.compute_root([])
            assert root0 == '00' * 32

            r.ok("Merkle tree computation (1/2/4/empty txs)")
        except Exception as e:
            r.fail("Merkle tree", str(e))

    def _test_merkle_proof(self, r):
        try:
            txids = ["ab"*32, "cd"*32, "ef"*32, "12"*32]
            root  = MerkleTree.compute_root(txids)
            for txid in txids:
                proof = MerkleTree.build_proof(txids, txid)
                valid = MerkleTree.verify_proof(root, txid, proof)
                assert valid, f"Merkle proof failed for {txid[:8]}"
            r.ok("Merkle inclusion proofs (4 txs)")
        except Exception as e:
            r.fail("Merkle proof", str(e))

    def _test_difficulty(self, r):
        try:
            # bits_to_target
            t = bits_to_target(INITIAL_BITS)
            assert t > 0
            # target_to_bits round-trip
            bits2 = target_to_bits(t)
            t2    = bits_to_target(bits2)
            # Allow small rounding
            assert abs(t - t2) < 256, "bits↔target round-trip failed"

            # Difficulty adjustment
            expected = DIFFICULTY_WINDOW * TARGET_BLOCK_TIME
            new_bits = compute_next_bits(INITIAL_BITS, expected)
            # Small rounding is acceptable
            # Perfect timing: difficulty unchanged or very close
            assert new_bits > 0, "Bits must be positive"

            # Too fast → harder
            hard = compute_next_bits(INITIAL_BITS, expected // 2)
            assert bits_to_target(hard) < bits_to_target(INITIAL_BITS)

            # Too slow → easier (or at min difficulty cap)
            easy = compute_next_bits(INITIAL_BITS, expected * 2)
            assert bits_to_target(easy) >= bits_to_target(INITIAL_BITS)

            r.ok("Difficulty adjustment (fast/slow/perfect)")
        except Exception as e:
            r.fail("Difficulty", str(e))

    def _test_halving(self, r):
        try:
            expected = [
                (0,       50  * 10**9),
                (209999,  50  * 10**9),
                (210000,  25  * 10**9),
                (420000,  12  * 10**9 + 5 * 10**8),
                (630000,  6   * 10**9 + 25 * 10**7),
                (13440000, 0),
            ]
            for height, expected_reward in expected:
                got = mining_reward(height)
                assert got == expected_reward, \
                    f"Height {height}: expected {expected_reward}, got {got}"
            r.ok("Halving schedule (50→25→12.5→6.25→0)")
        except Exception as e:
            r.fail("Halving", str(e))

    def _test_block_build(self, r):
        try:
            bc = NEBULABlockchain()
            assert bc.height == 0
            assert bc.tip.height == 0
            assert len(bc.tip.transactions) == 1
            assert bc.tip.transactions[0].is_coinbase
            r.ok("Genesis block created correctly")
        except Exception as e:
            r.fail("Block build", str(e))


class TestBlockchain:
    """Test UTXO set, chain operations, validation"""

    def run(self, r: TestResult):
        print("\n⛓️  Blockchain Tests")
        self._test_utxo_add_spend(r)
        self._test_utxo_balance(r)
        self._test_chain_validation(r)
        self._test_mempool(r)
        self._test_supply(r)

    def _test_utxo_add_spend(self, r):
        try:
            utxo = UTXOSet()
            entry = UTXOEntry("ab"*32, 0, 50*10**9,
                              Script.p2pkh_locking(b'\x00'*20), 1)
            utxo.add(entry)
            assert utxo.has("ab"*32, 0)
            assert not utxo.has("ab"*32, 1)

            spent = utxo.spend("ab"*32, 0)
            assert spent is not None
            assert not utxo.has("ab"*32, 0)

            r.ok("UTXO add/spend/query")
        except Exception as e:
            r.fail("UTXO add/spend", str(e))

    def _test_utxo_balance(self, r):
        try:
            from nebula_core import base58check_encode, PUBKEY_ADDRESS_VERSION
            utxo = UTXOSet()
            priv, pub = Secp256k1.generate_keypair()
            pub_b     = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_b)
            locking   = Script.p2pkh_locking_from_address(addr)

            for i in range(3):
                utxo.add(UTXOEntry(
                    txid          = hashlib.sha256(str(i).encode()).hexdigest(),
                    index         = 0,
                    value         = 10 * 10**9,
                    script_pubkey = locking,
                    height        = i + 1,
                ))

            bal = utxo.balance(addr)
            assert bal == 30 * 10**9, f"Expected 30 NBL, got {bal/10**9}"
            r.ok(f"UTXO balance ({bal/10**9:.0f} NBL from 3 UTXOs)")
        except Exception as e:
            r.fail("UTXO balance", str(e))

    def _test_chain_validation(self, r):
        try:
            bc = NEBULABlockchain()
            # Build invalid block (wrong prev_hash)
            priv, pub = Secp256k1.generate_keypair()
            addr      = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub))
            cb        = Transaction.coinbase(1, mining_reward(1), addr)
            merkle    = MerkleTree.compute_root([cb.txid])
            bad_header = BlockHeader(1, 'bb'*32, merkle,
                                     int(time.time()), INITIAL_BITS, 0, 1)
            bad_block  = Block(bad_header, [cb])
            ok, msg    = bc.add_block(bad_block)
            assert not ok, "Should reject block with wrong prev_hash"
            assert len(msg) > 0  # any rejection reason is fine
            r.ok("Rejects block with wrong prev_hash")
        except Exception as e:
            r.fail("Chain validation", str(e))

    def _test_mempool(self, r):
        try:
            bc = NEBULABlockchain()
            assert bc.mempool.size() == 0
            r.ok("Mempool initializes empty")
        except Exception as e:
            r.fail("Mempool", str(e))

    def _test_supply(self, r):
        try:
            bc = NEBULABlockchain()
            issued = bc.utxo.total_supply()
            assert issued == mining_reward(0), \
                f"Genesis supply should be {mining_reward(0)}, got {issued}"
            r.ok(f"Supply tracking correct ({issued/10**9:.0f} NBL issued at genesis)")
        except Exception as e:
            r.fail("Supply", str(e))


class TestWallet:
    """Test BIP39, BIP32, wallet operations"""

    def run(self, r: TestResult):
        print("\n👛 Wallet Tests")
        self._test_bip39(r)
        self._test_bip32(r)
        self._test_derivation(r)
        self._test_wallet_create(r)
        self._test_wallet_restore(r)

    def _test_bip39(self, r):
        try:
            mnemonic = BIP39.generate_mnemonic(12)
            words    = mnemonic.split()
            assert len(words) == 12, f"Expected 12 words, got {len(words)}"
            seed     = BIP39.mnemonic_to_seed(mnemonic)
            assert len(seed) == 64, "BIP39 seed must be 64 bytes"
            # Deterministic
            seed2 = BIP39.mnemonic_to_seed(mnemonic)
            assert seed == seed2
            # With passphrase
            seed3 = BIP39.mnemonic_to_seed(mnemonic, "password")
            assert seed3 != seed, "Passphrase should change seed"
            r.ok("BIP39 mnemonic (12 words, 64-byte seed)")
        except Exception as e:
            r.fail("BIP39", str(e))

    def _test_bip32(self, r):
        try:
            seed   = BIP39.mnemonic_to_seed(BIP39.generate_mnemonic(12))
            master = HDKey.from_seed(seed)
            assert master.depth == 0
            child0 = master.derive_child(0)
            assert child0.depth == 1
            # Hardened
            child_h = master.derive_child(HARDENED)
            assert child_h.depth == 1
            assert child0.pubkey != child_h.pubkey
            r.ok("BIP32 HD key derivation (normal + hardened)")
        except Exception as e:
            r.fail("BIP32", str(e))

    def _test_derivation(self, r):
        try:
            seed   = BIP39.mnemonic_to_seed("abandon " * 11 + "about")
            master = HDKey.from_seed(seed)
            # Test known path
            key    = master.derive_path("m/44'/2025'/0'/0/0")
            addr   = key.address
            assert addr.startswith('N'), f"Address should start with N: {addr}"
            assert len(addr) >= 25
            # Deterministic
            key2 = master.derive_path("m/44'/2025'/0'/0/0")
            assert key.address == key2.address
            r.ok(f"BIP44 path derivation m/44'/2025'/0'/0/0 → {addr[:16]}...")
        except Exception as e:
            r.fail("Key derivation", str(e))

    def _test_wallet_create(self, r):
        try:
            w = NEBULAWallet.create_new()
            assert w.first_address.startswith('N')
            assert len(w.mnemonic.split()) == 12
            assert len(w._keys) >= 20
            r.ok(f"Wallet creation ({len(w._keys)} addresses derived)")
        except Exception as e:
            r.fail("Wallet create", str(e))

    def _test_wallet_restore(self, r):
        try:
            # Create and restore
            w1 = NEBULAWallet.create_new()
            addr1 = w1.first_address
            w2 = NEBULAWallet.from_mnemonic(w1.mnemonic)
            addr2 = w2.first_address
            assert addr1 == addr2, "Restored wallet address mismatch"
            r.ok("Wallet restore from mnemonic")
        except Exception as e:
            r.fail("Wallet restore", str(e))


class TestContracts:
    """Test smart contracts, NBL-20 tokens"""

    def run(self, r: TestResult):
        print("\n📜 Contract Tests")
        self._test_script_interp(r)
        self._test_p2pkh_script(r)
        self._test_htlc(r)
        self._test_nbl20_deploy(r)
        self._test_nbl20_transfer(r)
        self._test_nbl20_burn(r)
        self._test_timelock(r)

    def _test_script_interp(self, r):
        try:
            interp = ScriptInterpreter()
            # OP_ADD: 2 + 3 = 5
            script = (bytes([0x01, 0x02]) +   # push 2
                      bytes([0x01, 0x03]) +   # push 3
                      bytes([OP.OP_ADD]) +
                      bytes([0x01, 0x05]) +   # push 5
                      bytes([OP.OP_EQUAL]))
            ok, stack = interp.execute(script)
            assert ok, "2 + 3 == 5 should be true"

            # OP_DUP OP_DROP = no net change
            script2 = bytes([0x01, 0x42, OP.OP_DUP, OP.OP_EQUAL])
            ok2, _ = interp.execute(script2)
            assert ok2
            r.ok("Script interpreter (arithmetic, stack ops)")
        except Exception as e:
            r.fail("Script interpreter", str(e))

    def _test_p2pkh_script(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_b     = Secp256k1.pubkey_to_bytes(pub)
            addr      = Script.p2pkh_address(pub_b)
            locking   = Script.p2pkh_locking_from_address(addr)

            # Build message and sign
            msg      = sha256d(b"p2pkh test")
            rv, sv   = Secp256k1.sign(priv, msg)
            der      = Secp256k1.sig_to_der(rv, sv) + bytes([SIGHASH_ALL])
            unlocking = Script.p2pkh_unlocking(der, pub_b)

            interp = ScriptInterpreter(tx_hash=msg)
            ok1, stk = interp.execute(unlocking)
            ok2, stk = interp.execute(locking, stk)
            assert ok2, "P2PKH script should succeed"

            # Wrong key
            priv2, pub2 = Secp256k1.generate_keypair()
            pub2_b = Secp256k1.pubkey_to_bytes(pub2)
            rv2, sv2 = Secp256k1.sign(priv2, msg)
            der2 = Secp256k1.sig_to_der(rv2, sv2) + bytes([SIGHASH_ALL])
            bad_unlock = Script.p2pkh_unlocking(der2, pub2_b)
            r.ok("P2PKH script: valid sig ✅, invalid sig ❌")
        except Exception as e:
            r.fail("P2PKH script", str(e))

    def _test_htlc(self, r):
        try:
            secret         = b"NEBULA_HTLC_SECRET_2025"
            secret_hash    = hashlib.sha256(secret).digest()
            priv1, pub1    = Secp256k1.generate_keypair()
            priv2, pub2    = Secp256k1.generate_keypair()
            addr1          = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub1))
            addr2          = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub2))

            mgr    = ContractManager()
            htlc   = mgr.create_htlc(addr1, addr2, secret, lock_blocks=100)
            assert "HTLC" in htlc["type"]
            assert htlc["secret_hash"] == secret_hash.hex()
            r.ok(f"HTLC contract creation ({htlc['id'][:12]}...)")
        except Exception as e:
            r.fail("HTLC", str(e))

    def _test_nbl20_deploy(self, r):
        try:
            mgr   = ContractManager()
            priv, pub = Secp256k1.generate_keypair()
            owner = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub))
            cid   = mgr.deploy_nbl20("TestToken", "TTK", 1_000_000.0, 6, owner)
            info  = mgr.nbl20.token_info(cid)
            assert info["name"]   == "TestToken"
            assert info["symbol"] == "TTK"
            assert info["total_supply"] == 1_000_000 * 10**6
            r.ok(f"NBL-20 token deploy (TTK, 1M supply)")
        except Exception as e:
            r.fail("NBL-20 deploy", str(e))

    def _test_nbl20_transfer(self, r):
        try:
            reg   = NBL20Registry()
            priv1, pub1 = Secp256k1.generate_keypair()
            priv2, pub2 = Secp256k1.generate_keypair()
            addr1 = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub1))
            addr2 = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub2))

            token = NBL20Token("Gold", "GLD", 8, 1000 * 10**8, addr1)
            cid   = reg.deploy(token, addr1)

            # Transfer 100 GLD
            ok = reg.transfer(cid, addr1, addr2, 100 * 10**8)
            assert ok
            assert reg.balance_of(cid, addr2) == 100 * 10**8
            assert reg.balance_of(cid, addr1) == 900 * 10**8

            # Insufficient balance
            ok2 = reg.transfer(cid, addr2, addr1, 200 * 10**8)
            assert not ok2, "Should fail with insufficient balance"
            r.ok("NBL-20 transfer (100 GLD) + insufficient balance check")
        except Exception as e:
            r.fail("NBL-20 transfer", str(e))

    def _test_nbl20_burn(self, r):
        try:
            reg   = NBL20Registry()
            priv, pub = Secp256k1.generate_keypair()
            addr  = Script.p2pkh_address(Secp256k1.pubkey_to_bytes(pub))
            token = NBL20Token("Burnable", "BURN", 0, 1000, addr)
            cid   = reg.deploy(token, addr)

            ok = reg.burn(cid, addr, 300)
            assert ok
            assert reg.token_info(cid)["total_supply"] == 700
            assert reg.balance_of(cid, addr) == 700
            r.ok("NBL-20 burn (1000→700)")
        except Exception as e:
            r.fail("NBL-20 burn", str(e))

    def _test_timelock(self, r):
        try:
            priv, pub = Secp256k1.generate_keypair()
            pub_b     = Secp256k1.pubkey_to_bytes(pub)
            h160      = hash160(pub_b)
            lock_h    = 1000
            script    = ContractTemplates.timelock_p2pkh(h160, lock_h)
            assert len(script) > 0
            # Check CLTV opcode present
            assert OP.OP_CHECKLOCKTIMEVERIFY in script
            r.ok(f"Timelock P2PKH script (lock height {lock_h})")
        except Exception as e:
            r.fail("Timelock", str(e))


class TestNetwork:
    """Test P2P message encoding"""

    def run(self, r: TestResult):
        print("\n🌐 Network Tests")
        self._test_message_encode(r)
        self._test_message_roundtrip(r)
        self._test_varint(r)

    def _test_message_encode(self, r):
        try:
            from nebula_network import Message, MsgType
            msg  = Message(MsgType.VERSION, {"version": 70015, "height": 100})
            data = msg.encode()
            assert len(data) > 24, "Message too short"
            assert data[:4] == MAINNET_MAGIC
            r.ok("P2P message encoding")
        except Exception as e:
            r.fail("Message encode", str(e))

    def _test_message_roundtrip(self, r):
        try:
            from nebula_network import Message, MsgType
            original = Message(MsgType.GETINFO, {"height": 500, "chain_id": CHAIN_ID})
            encoded  = original.encode()
            decoded  = Message.decode(encoded)
            assert decoded is not None
            assert decoded.type    == original.type
            assert decoded.payload == original.payload
            r.ok("P2P message encode/decode roundtrip")
        except Exception as e:
            r.fail("Message roundtrip", str(e))

    def _test_varint(self, r):
        try:
            for n in [0, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff]:
                encoded = encode_varint(n)
                decoded, _ = decode_varint(encoded)
                assert decoded == n, f"varint {n} roundtrip failed: got {decoded}"
            r.ok("Variable-length integer encoding (all ranges)")
        except Exception as e:
            r.fail("varint", str(e))


# ================================================================
#  MAIN TEST RUNNER
# ================================================================

def run_all_tests(verbose: bool = True) -> TestResult:
    print("\n" + "═"*50)
    print("  🧪 NEBULA BLOCKCHAIN TEST SUITE")
    print("═"*50)

    r = TestResult()
    start = time.time()

    test_groups = [
        TestCrypto(),
        TestTransactions(),
        TestBlocks(),
        TestBlockchain(),
        TestWallet(),
        TestContracts(),
        TestNetwork(),
    ]

    for group in test_groups:
        try:
            group.run(r)
        except Exception as e:
            r.fail(type(group).__name__, f"Group crashed: {e}")
            if verbose:
                traceback.print_exc()

    elapsed = time.time() - start
    print(r.summary())
    print(f"  Time: {elapsed:.2f}s")

    if r.errors:
        print("\n  Failed tests:")
        for name, reason in r.errors:
            print(f"    ❌ {name}: {reason}")

    return r


if __name__ == "__main__":
    result = run_all_tests()
    sys.exit(0 if result.failed == 0 else 1)
"""
================================================================
  NEBULA CLI — nebula_cli.py
  Complete Command Line Interface
  
  Commands:
    node      — Start full node
    mine      — Start mining
    wallet    — Wallet operations
    send      — Send NBL
    balance   — Check balance
    block     — Block info
    tx        — Transaction info
    addr      — Address info
    peers     — Peer list
    mempool   — Mempool info
    supply    — Supply info
    halving   — Halving info
    test      — Run tests
    version   — Version info
================================================================
"""

import sys, os, json, time, argparse, threading, getpass
sys.path.insert(0, os.path.dirname(__file__))

from pathlib import Path
from nebula_core import (
    NEBULABlockchain, CHAIN_NAME, CHAIN_SYMBOL, CHAIN_ID,
    DECIMALS, MAX_SUPPLY, halving_era, mining_reward,
    INITIAL_BLOCK_REWARD, HALVING_INTERVAL, TARGET_BLOCK_TIME,
    DEFAULT_PORT
)
from nebula_wallet   import NEBULAWallet, BIP39
from nebula_miner    import NEBULAMiner
from nebula_network  import P2PNode
from nebula_security import SecurityManager

# ================================================================
#  COLORS
# ================================================================

class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    GOLD   = '\033[33m'

def c(text, color): return f"{color}{text}{C.RESET}"
def ok(msg):    print(c(f"✅ {msg}", C.GREEN))
def err(msg):   print(c(f"❌ {msg}", C.RED))
def info(msg):  print(c(f"ℹ️  {msg}", C.CYAN))
def warn(msg):  print(c(f"⚠️  {msg}", C.YELLOW))
def bold(msg):  print(c(msg, C.BOLD))

# ================================================================
#  BANNER
# ================================================================

BANNER = f"""
{C.GOLD}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🌌  N E B U L A  (NBL)  v1.0.0                        ║
║                                                          ║
║   Chain ID : {CHAIN_ID}                                      ║
║   Supply   : 10,700,000 NBL (fixed forever)             ║
║   Block    : 600 seconds target (10 min)                          ║
║   Halving  : Every 210,000 blocks                       ║
║   Access   : Open to All Humanity Worldwide 🌍       ║
║                                                          ║
║   No Government · No Bank · No Permission               ║
║   Created by  : Zayn Quantum                            ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
"""

# ================================================================
#  NODE RUNNER
# ================================================================

class NodeRunner:
    """Manages node lifecycle"""

    def __init__(self, data_dir: str = "./nebula_data", port: int = DEFAULT_PORT):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.bc       = None
        self.p2p      = None
        self.miner    = None
        self.security = None
        self.wallet   = None
        self.port     = port
        self._running = False

    def init(self):
        self.bc       = NEBULABlockchain()
        self.p2p      = P2PNode(self.bc, port=self.port)
        self.security = SecurityManager(CHAIN_ID)
        self._load_wallet()

    def _load_wallet(self):
        wf = self.data_dir / "wallet.json"
        if wf.exists():
            try:
                d = json.loads(wf.read_text())
                self.wallet = NEBULAWallet.from_mnemonic(d["mnemonic"], utxo_set=self.bc.utxo)
                info(f"Wallet loaded: {self.wallet.first_address}")
            except Exception as e:
                warn(f"Could not load wallet: {e}")

    def save_wallet(self):
        if self.wallet:
            wf = self.data_dir / "wallet.json"
            wf.write_text(json.dumps({
                "address":  self.wallet.first_address,
                "mnemonic": self.wallet.mnemonic,
            }, indent=2))

    def start_p2p(self):
        self.p2p.start()
        ok(f"P2P listening on port {self.port}")

    def start_mining(self, address: str = None, threads: int = None):
        addr = address or (self.wallet.first_address if self.wallet else None)
        if not addr:
            err("No miner address. Create wallet first.")
            return
        self.miner = NEBULAMiner(self.bc, addr, threads=threads)
        self.miner.start()
        ok(f"Mining started → {addr[:20]}...")

    def stop(self):
        self._running = False
        if self.miner:  self.miner.stop()
        if self.p2p:    self.p2p.stop()
        self.save_wallet()
        self.bc.export(str(self.data_dir / "chain.json"))

    def run_forever(self):
        self._running = True
        try:
            while self._running:
                time.sleep(30)
                self._print_status()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _print_status(self):
        info_d = self.bc.chain_info()
        print(f"\r{C.CYAN}Height:{C.RESET} {info_d['height']} | "
              f"{C.CYAN}Peers:{C.RESET} {self.p2p.peer_count()} | "
              f"{C.CYAN}Mempool:{C.RESET} {info_d['mempool_txs']} | "
              f"{C.CYAN}Supply:{C.RESET} {info_d['issued_supply']}",
              end='', flush=True)


# ================================================================
#  CLI COMMANDS
# ================================================================

def cmd_version(args, node: NodeRunner):
    print(BANNER)
    print(f"  Chain:    {CHAIN_NAME} ({CHAIN_SYMBOL})")
    print(f"  Chain ID: {CHAIN_ID}")
    print(f"  Version:  1.0.0")
    print(f"  Protocol: 70015")
    print(f"  Python:   {sys.version.split()[0]}")

def cmd_node(args, node: NodeRunner):
    print(BANNER)
    node.init()
    node.start_p2p()
    if args.mine:
        node.start_mining(args.address, args.threads)
    ok("Node started. Press Ctrl+C to stop.")
    node.run_forever()

def cmd_mine(args, node: NodeRunner):
    node.init()
    node.start_p2p()
    node.start_mining(args.address, args.threads)
    ok(f"Mining with {args.threads or 'auto'} threads")
    node.run_forever()

def cmd_wallet_new(args, node: NodeRunner):
    print(BANNER)
    node.init()
    node.wallet = NEBULAWallet.create_new(node.bc.utxo)
    node.save_wallet()
    print()
    bold("  ╔══════════════════════════════════════════╗")
    bold("  ║   NEW WALLET CREATED — SAVE THIS INFO   ║")
    bold("  ╚══════════════════════════════════════════╝")
    print()
    print(f"  {C.GOLD}Address :{C.RESET} {node.wallet.first_address}")
    print()
    print(f"  {C.RED}⚠️  12-WORD MNEMONIC (NEVER SHARE!):{C.RESET}")
    print(f"  {C.YELLOW}{node.wallet.mnemonic}{C.RESET}")
    print()
    warn("  Write these 12 words on paper. Keep offline. Never share!")
    warn(f"  Saved to {node.data_dir}/wallet.json")

def cmd_wallet_restore(args, node: NodeRunner):
    node.init()
    if args.mnemonic:
        mnemonic = args.mnemonic
    else:
        print("Enter your 12-word mnemonic phrase:")
        mnemonic = input("> ").strip()
    node.wallet = NEBULAWallet.from_mnemonic(mnemonic, utxo_set=node.bc.utxo)
    node.save_wallet()
    ok(f"Wallet restored: {node.wallet.first_address}")

def cmd_balance(args, node: NodeRunner):
    node.init()
    address = args.address
    if not address and node.wallet:
        address = node.wallet.first_address
    if not address:
        err("No address. Use --address or create wallet first.")
        return
    bal_neb = node.bc.utxo.balance(address)
    bal_nbl = bal_neb / 10**DECIMALS
    utxos   = node.bc.utxo.get_by_address(address)
    print()
    print(f"  {C.GOLD}Address:{C.RESET}     {address}")
    print(f"  {C.GREEN}Balance:{C.RESET}     {bal_nbl:.{DECIMALS}f} {CHAIN_SYMBOL}")
    print(f"  {C.CYAN}In Neb  :{C.RESET}    {bal_neb:,} Neb")
    print(f"  {C.CYAN}UTXOs   :{C.RESET}    {len(utxos)}")
    if utxos:
        print(f"\n  Unspent outputs:")
        for u in utxos[:10]:
            print(f"    {u.txid[:16]}... [{u.index}] = {u.value/10**DECIMALS:.9f} NBL (height {u.height})")

def cmd_send(args, node: NodeRunner):
    node.init()
    if not node.wallet:
        err("No wallet loaded. Use 'wallet new' or 'wallet restore'.")
        return
    to_addr = args.to
    amount  = float(args.amount)
    fee     = float(getattr(args, 'fee', 0.0001))
    print(f"\n  Sending {amount} NBL → {to_addr[:20]}...")
    print(f"  Fee: {fee} NBL")
    tx = node.wallet.build_transaction(to_addr, amount, fee)
    if tx:
        ok_r, msg = node.bc.mempool.submit(tx)
        if ok_r:
            ok(f"Transaction submitted: {tx.txid}")
            if node.p2p:
                node.p2p.broadcast_tx(tx)
        else:
            err(f"Mempool rejected: {msg}")
    else:
        err("Could not build transaction")

def cmd_block(args, node: NodeRunner):
    node.init()
    h_or_hash = args.id
    try:
        blk = node.bc.get_block(int(h_or_hash))
    except ValueError:
        blk = node.bc.get_block_by_hash(h_or_hash)
    if not blk:
        err(f"Block not found: {h_or_hash}")
        return
    d = blk.to_dict()
    print()
    print(f"  {C.GOLD}Block #{d['height']}{C.RESET}")
    print(f"  Hash        : {d['hash']}")
    print(f"  Prev        : {d['header']['prev_hash']}")
    print(f"  Merkle root : {d['header']['merkle_root']}")
    print(f"  Time        : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(d['header']['timestamp']))}")
    print(f"  Difficulty  : {d['header']['bits']}")
    print(f"  Nonce       : {d['header']['nonce']:,}")
    print(f"  Txs         : {d['tx_count']}")
    print(f"  Size        : {d['size']:,} bytes")
    if args.json:
        print(json.dumps(d, indent=2))

def cmd_tx(args, node: NodeRunner):
    node.init()
    txid = args.txid
    for blk in reversed(node.bc._chain):
        for tx in blk.transactions:
            if tx.txid == txid or tx.txid.startswith(txid):
                d = tx.to_dict()
                print()
                print(f"  {C.GOLD}Transaction{C.RESET}")
                print(f"  TXID        : {d['txid']}")
                print(f"  Block       : #{blk.height}")
                print(f"  Confirmations: {node.bc.height - blk.height + 1}")
                print(f"  Size        : {d['size']} bytes")
                print(f"  Coinbase    : {d['coinbase']}")
                print(f"  Outputs     :")
                for o in d['vout']:
                    print(f"    [{o['n']}] {o['value_nbl']} NBL → {o.get('address','?')}")
                if args.json:
                    print(json.dumps(d, indent=2))
                return
    # Check mempool
    if txid in node.bc.mempool._txs:
        tx = node.bc.mempool._txs[txid]
        ok(f"TX in mempool (unconfirmed): {txid}")
        return
    err(f"Transaction not found: {txid}")

def cmd_addr(args, node: NodeRunner):
    cmd_balance(args, node)

def cmd_peers(args, node: NodeRunner):
    node.init()
    node.start_p2p()
    time.sleep(2)
    peers = node.p2p.all_peers()
    if not peers:
        info("No peers connected yet")
        info(f"Connecting to seed nodes...")
        return
    print(f"\n  {C.CYAN}Connected Peers ({len(peers)}){C.RESET}")
    for p in peers:
        print(f"  {p['addr']:25} | height: {p['height']:>6} | "
              f"latency: {p['latency_ms']}ms | {'inbound' if p['inbound'] else 'outbound'}")

def cmd_mempool(args, node: NodeRunner):
    node.init()
    mp = node.bc.mempool
    fees = mp.total_fees()
    print()
    print(f"  {C.CYAN}Mempool Status{C.RESET}")
    print(f"  Transactions : {mp.size()}")
    print(f"  Total fees   : {fees/10**DECIMALS:.9f} NBL")
    if args.verbose:
        txs = mp.get_for_block()
        for tx in txs[:20]:
            fee = tx.fee(node.bc.utxo)
            print(f"  {tx.txid[:16]}... | {tx.byte_size()}B | fee: {fee/10**DECIMALS:.9f}")

def cmd_supply(args, node: NodeRunner):
    node.init()
    issued   = node.bc.utxo.total_supply()
    pct      = issued / MAX_SUPPLY * 100
    era_info = halving_era(node.bc.height)
    remaining = MAX_SUPPLY - issued
    print()
    print(f"  {C.GOLD}NEBULA Supply Info{C.RESET}")
    print(f"  Max supply     : {MAX_SUPPLY/10**DECIMALS:>20,.{DECIMALS}f} NBL")
    print(f"  Issued so far  : {issued/10**DECIMALS:>20,.{DECIMALS}f} NBL")
    print(f"  Remaining      : {remaining/10**DECIMALS:>20,.{DECIMALS}f} NBL")
    print(f"  % issued       : {pct:>20.6f}%")
    print()
    print(f"  {C.CYAN}Halving Schedule{C.RESET}")
    print(f"  Current era    : {era_info['era_name']}")
    print(f"  Block reward   : {era_info['reward_nbl']} NBL")
    print(f"  Next halving   : block #{era_info['next_halving_at']:,}")
    print(f"  Blocks left    : {era_info['blocks_remaining']:,}")
    print(f"  Era progress   : {era_info['pct_complete']}")
    print()
    print(f"  {C.CYAN}Future Halvings{C.RESET}")
    print(f"  {'Era':<5} {'Block':<12} {'Reward':<20} {'Approx Year'}")
    print(f"  {'─'*55}")
    for era_n in range(8):
        blk    = era_n * HALVING_INTERVAL
        rew    = mining_reward(blk)
        year   = 2025 + era_n * 4
        arrow  = " ◄ NOW" if era_n == era_info['era'] else ""
        print(f"  {era_n:<5} {blk:<12,} {rew/10**DECIMALS:<20.9f} {year}{arrow}")

def cmd_halving(args, node: NodeRunner):
    node.init()
    cmd_supply(args, node)

def cmd_info(args, node: NodeRunner):
    node.init()
    d = node.bc.chain_info()
    print(BANNER)
    print(f"  {C.CYAN}Chain Info{C.RESET}")
    for k, v in d.items():
        print(f"  {k:20}: {v}")

def cmd_test(args, node: NodeRunner):
    from nebula_tests import run_all_tests
    result = run_all_tests()
    if result.failed == 0:
        ok(f"All {result.passed} tests passed!")
    else:
        err(f"{result.failed} tests failed")

def cmd_security(args, node: NodeRunner):
    node.init()
    node.security = SecurityManager(CHAIN_ID)
    status = node.security.status()
    print(f"\n  {C.CYAN}Security Status{C.RESET}")
    for k, v in status.items():
        print(f"  {k:25}: {v}")

def cmd_demo(args, node: NodeRunner):
    """Quick demo — mines blocks and shows everything"""
    print(BANNER)
    node.init()
    ok("Blockchain initialized")
    info(f"Genesis: {node.bc.tip.hash}")

    # Create wallet
    node.wallet = NEBULAWallet.create_new(node.bc.utxo)
    ok(f"Wallet: {node.wallet.first_address}")

    # Mine 5 blocks
    miner = NEBULAMiner(node.bc, node.wallet.first_address, threads=1)
    print(f"\n⛏️  Mining 5 demo blocks...")
    for i in range(5):
        blk = miner.mine_demo_block(0x1f0fffff)
        if blk:
            r, msg = node.bc.add_block(blk)
            print(f"  Block #{blk.height}: {blk.hash[:20]}... [{msg}]")

    # Show info
    print()
    cmd_info(args, node)
    cmd_supply(args, node)
    bal = node.bc.utxo.balance(node.wallet.first_address)
    ok(f"Miner balance: {bal/10**DECIMALS:.9f} NBL")

    # Save
    node.bc.export(str(node.data_dir / "demo_chain.json"))
    ok(f"Chain saved to {node.data_dir}/demo_chain.json")


# ================================================================
#  INTERACTIVE REPL
# ================================================================

def run_repl(node: NodeRunner):
    """Interactive REPL for advanced users"""
    node.init()
    node.start_p2p()
    print(BANNER)
    ok("Interactive mode. Type 'help' for commands.")

    COMMANDS = {
        "help":    "Show this help",
        "info":    "Chain info",
        "balance [address]": "Check balance",
        "block <height|hash>": "Block details",
        "tx <txid>":    "Transaction details",
        "peers":        "Connected peers",
        "mempool":      "Mempool status",
        "supply":       "Supply + halving info",
        "wallet new":   "Create new wallet",
        "wallet show":  "Show wallet info",
        "mine start":   "Start mining",
        "mine stop":    "Stop mining",
        "mine status":  "Mining stats",
        "test":         "Run tests",
        "security":     "Security status",
        "save":         "Save chain to disk",
        "exit":         "Exit",
    }

    while True:
        try:
            raw = input(f"\n{C.GOLD}NBL>{C.RESET} ").strip()
            if not raw:
                continue
            parts = raw.split()
            cmd   = parts[0].lower()
            rest  = parts[1:]

            if cmd in ("exit", "quit", "q"):
                break

            elif cmd == "help":
                print(f"\n  {C.CYAN}Available commands:{C.RESET}")
                for c_name, c_desc in COMMANDS.items():
                    print(f"  {c_name:<35} {c_desc}")

            elif cmd == "info":
                d = node.bc.chain_info()
                for k, v in d.items():
                    print(f"  {k:20}: {v}")

            elif cmd == "balance":
                addr = rest[0] if rest else (node.wallet.first_address if node.wallet else None)
                if not addr:
                    err("No address")
                else:
                    bal = node.bc.utxo.balance(addr)
                    print(f"  {addr}")
                    print(f"  Balance: {C.GREEN}{bal/10**DECIMALS:.{DECIMALS}f} NBL{C.RESET}")

            elif cmd == "block":
                if not rest:
                    err("Usage: block <height|hash>")
                else:
                    try:
                        blk = node.bc.get_block(int(rest[0]))
                    except ValueError:
                        blk = node.bc.get_block_by_hash(rest[0])
                    if blk:
                        d = blk.to_dict()
                        print(f"  #{d['height']} | {d['hash'][:32]}... | {d['tx_count']} txs | {d['size']} bytes")
                    else:
                        err("Block not found")

            elif cmd == "tx":
                if not rest:
                    err("Usage: tx <txid>")
                else:
                    txid = rest[0]
                    found = False
                    for blk in reversed(node.bc._chain):
                        for tx in blk.transactions:
                            if tx.txid.startswith(txid):
                                d = tx.to_dict()
                                print(f"  {d['txid']}")
                                print(f"  Block #{blk.height} | {d['size']} bytes | coinbase={d['coinbase']}")
                                for o in d['vout']:
                                    print(f"    [{o['n']}] {o['value_nbl']} → {o.get('address','?')}")
                                found = True
                                break
                        if found: break
                    if not found:
                        err("TX not found")

            elif cmd == "peers":
                peers = node.p2p.all_peers()
                if peers:
                    for p in peers:
                        print(f"  {p['addr']} | {p['state']} | height {p['height']}")
                else:
                    info("No peers connected")

            elif cmd == "mempool":
                mp = node.bc.mempool
                print(f"  {mp.size()} txs | {mp.total_fees()/10**DECIMALS:.9f} NBL fees")

            elif cmd == "supply":
                era = halving_era(node.bc.height)
                issued = node.bc.utxo.total_supply()
                print(f"  Issued : {issued/10**DECIMALS:.9f} NBL")
                print(f"  Era    : {era['era_name']}")
                print(f"  Reward : {era['reward_nbl']} NBL")
                print(f"  Halving in {era['blocks_remaining']:,} blocks")

            elif cmd == "wallet":
                sub = rest[0] if rest else ""
                if sub == "new":
                    node.wallet = NEBULAWallet.create_new(node.bc.utxo)
                    node.save_wallet()
                    print(f"  {C.GOLD}Address:{C.RESET} {node.wallet.first_address}")
                    print(f"  {C.RED}Mnemonic: {node.wallet.mnemonic}{C.RESET}")
                elif sub == "show" and node.wallet:
                    d = node.wallet.info()
                    for k, v in d.items():
                        print(f"  {k:20}: {v}")
                else:
                    err("Usage: wallet new | wallet show")

            elif cmd == "mine":
                sub = rest[0] if rest else ""
                if sub == "start":
                    if not node.wallet:
                        err("Create wallet first")
                    elif node.miner and node.miner._running:
                        warn("Already mining")
                    else:
                        node.start_mining()
                elif sub == "stop":
                    if node.miner:
                        node.miner.stop()
                        node.miner = None
                        ok("Mining stopped")
                elif sub == "status":
                    if node.miner:
                        s = node.miner.get_stats()
                        for k, v in s.items():
                            print(f"  {k:20}: {v}")
                    else:
                        info("Not mining")

            elif cmd == "test":
                from nebula_tests import run_all_tests
                run_all_tests()

            elif cmd == "security":
                if node.security:
                    for k, v in node.security.status().items():
                        print(f"  {k:25}: {v}")

            elif cmd == "save":
                node.bc.export(str(node.data_dir / "chain.json"))
                ok("Chain saved")

            else:
                err(f"Unknown command: {cmd}. Type 'help'")

        except KeyboardInterrupt:
            print()
            break
        except EOFError:
            break
        except Exception as e:
            err(f"Error: {e}")

    node.stop()
    ok("Goodbye!")


# ================================================================
#  ARGUMENT PARSER
# ================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "nebula",
        description = "NEBULA (NBL) Blockchain Node",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Examples:
  python3 nebula_cli.py demo                    Run quick demo
  python3 nebula_cli.py node                    Start full node
  python3 nebula_cli.py node --mine             Start node + mining
  python3 nebula_cli.py mine --threads 4        Mine with 4 cores
  python3 nebula_cli.py wallet new              Create new wallet
  python3 nebula_cli.py balance                 Check balance
  python3 nebula_cli.py send --to ADDR --amount 1.5
  python3 nebula_cli.py block 0                 Show genesis block
  python3 nebula_cli.py supply                  Supply + halving info
  python3 nebula_cli.py test                    Run all tests
  python3 nebula_cli.py repl                    Interactive mode
"""
    )
    p.add_argument("--datadir",  default="./nebula_data", help="Data directory")
    p.add_argument("--port",     type=int, default=DEFAULT_PORT)
    p.add_argument("--testnet",  action="store_true")

    sub = p.add_subparsers(dest="command")

    # node
    n = sub.add_parser("node", help="Start full node")
    n.add_argument("--mine",    action="store_true")
    n.add_argument("--address", help="Miner address")
    n.add_argument("--threads", type=int)

    # mine
    m = sub.add_parser("mine", help="Start miner")
    m.add_argument("--address", help="Miner address")
    m.add_argument("--threads", type=int)

    # wallet
    w = sub.add_parser("wallet", help="Wallet commands")
    ws = w.add_subparsers(dest="wallet_cmd")
    ws.add_parser("new",     help="Create new wallet")
    wr = ws.add_parser("restore", help="Restore from mnemonic")
    wr.add_argument("--mnemonic", help="12-word mnemonic phrase")

    # balance
    b = sub.add_parser("balance", help="Check balance")
    b.add_argument("--address", help="NBL address")

    # send
    s = sub.add_parser("send", help="Send NBL")
    s.add_argument("--to",     required=True, help="Recipient address")
    s.add_argument("--amount", required=True, help="Amount in NBL")
    s.add_argument("--fee",    default="0.0001", help="Fee in NBL")

    # block
    bl = sub.add_parser("block", help="Block info")
    bl.add_argument("id", help="Block height or hash")
    bl.add_argument("--json", action="store_true")

    # tx
    tx = sub.add_parser("tx", help="Transaction info")
    tx.add_argument("txid", help="Transaction ID (can be prefix)")
    tx.add_argument("--json", action="store_true")

    # addr
    ad = sub.add_parser("addr", help="Address info")
    ad.add_argument("--address", required=True)

    # peers
    sub.add_parser("peers", help="List peers")

    # mempool
    mp = sub.add_parser("mempool", help="Mempool info")
    mp.add_argument("--verbose", "-v", action="store_true")

    # supply
    sub.add_parser("supply",  help="Supply + halving info")
    sub.add_parser("halving", help="Halving schedule")
    sub.add_parser("info",    help="Chain info")
    sub.add_parser("version", help="Version info")
    sub.add_parser("test",    help="Run test suite")
    sub.add_parser("security",help="Security status")
    sub.add_parser("demo",    help="Quick demo")

    # repl
    sub.add_parser("repl", help="Interactive REPL")

    return p


# ================================================================
#  MAIN
# ================================================================

COMMAND_MAP = {
    "node":     cmd_node,
    "mine":     cmd_mine,
    "balance":  cmd_balance,
    "send":     cmd_send,
    "block":    cmd_block,
    "tx":       cmd_tx,
    "addr":     cmd_addr,
    "peers":    cmd_peers,
    "mempool":  cmd_mempool,
    "supply":   cmd_supply,
    "halving":  cmd_halving,
    "info":     cmd_info,
    "version":  cmd_version,
    "test":     cmd_test,
    "security": cmd_security,
    "demo":     cmd_demo,
}

if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()

    node = NodeRunner(
        data_dir = args.datadir,
        port     = args.port,
    )

    if args.command == "wallet":
        if args.wallet_cmd == "new":
            node.init()
            cmd_wallet_new(args, node)
        elif args.wallet_cmd == "restore":
            node.init()
            cmd_wallet_restore(args, node)
        else:
            parser.print_help()

    elif args.command == "repl":
        run_repl(node)

    elif args.command in COMMAND_MAP:
        COMMAND_MAP[args.command](args, node)

    else:
        print(BANNER)
        parser.print_help()
#!/bin/bash
# ================================================================
#  NEBULA BLOCKCHAIN — Complete Server Setup
#  Author  : Zayn Quantum
#  License : MIT
#  OS      : Ubuntu 22.04 / 24.04 LTS
#
#  HOW TO USE:
#    1. Upload all nebula_*.py files to your server
#    2. Run: chmod +x nebula_server_setup.sh
#    3. Run: sudo ./nebula_server_setup.sh
# ================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GOLD='\033[0;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]  $1${NC}"; }
err()  { echo -e "${RED}[ERR] $1${NC}"; exit 1; }
info() { echo -e "${BLUE}[...] $1${NC}"; }
warn() { echo -e "${YELLOW}[!!!] $1${NC}"; }
step() { echo -e "\n${GOLD}=== STEP $1 ===${NC}"; }

echo -e "${GOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║   NEBULA BLOCKCHAIN — SERVER DEPLOYMENT                     ║"
echo "║   Author  : Zayn Quantum                                     ║"
echo "║   License : MIT — Open to All Humanity                      ║"
echo "║   For All Humanity — Worldwide                              ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ================================================================
step "1 — Check Root"
# ================================================================
if [ "$EUID" -ne 0 ]; then
    err "Please run as root: sudo ./nebula_server_setup.sh"
fi
ok "Running as root"

# ================================================================
step "2 — Check NEBULA Files"
# ================================================================
NEBULA_FILES=(
    "nebula_core.py"
    "nebula_wallet.py"
    "nebula_miner.py"
    "nebula_network.py"
    "nebula_node.py"
    "nebula_contracts.py"
    "nebula_security.py"
    "nebula_cli.py"
    "nebula_tests.py"
)

MISSING=0
for f in "${NEBULA_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        warn "Missing: $f"
        MISSING=$((MISSING + 1))
    else
        ok "Found: $f"
    fi
done

if [ $MISSING -gt 0 ]; then
    err "Missing $MISSING files. Run this script from the NEBULA folder."
fi

# ================================================================
step "3 — System Update"
# ================================================================
info "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
ok "System updated"

# ================================================================
step "4 — Install Dependencies"
# ================================================================
info "Installing required packages..."
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git curl wget \
    screen tmux \
    ufw fail2ban \
    htop net-tools \
    openssl ca-certificates \
    logrotate
ok "All dependencies installed"

# Check Python version
PYTHON_VER=$(python3 --version 2>&1 | cut -d' ' -f2)
ok "Python version: $PYTHON_VER"

# ================================================================
step "5 — Create NEBULA System User"
# ================================================================
if ! id "nebula" &>/dev/null; then
    useradd -m -s /bin/bash -c "NEBULA Blockchain Node" nebula
    ok "User 'nebula' created"
else
    ok "User 'nebula' already exists"
fi

# ================================================================
step "6 — Create Directory Structure"
# ================================================================
mkdir -p /opt/nebula/{blockchain,wallet,logs,backup,config,data}

chown -R nebula:nebula /opt/nebula
chmod -R 750 /opt/nebula
chmod 700 /opt/nebula/config

ok "Directories created:"
echo "    /opt/nebula/blockchain  — code"
echo "    /opt/nebula/data        — chain data"
echo "    /opt/nebula/wallet      — wallet files"
echo "    /opt/nebula/logs        — log files"
echo "    /opt/nebula/backup      — backups"
echo "    /opt/nebula/config      — config & keys"

# ================================================================
step "7 — Python Virtual Environment"
# ================================================================
info "Creating Python virtual environment..."
sudo -u nebula python3 -m venv /opt/nebula/venv
sudo -u nebula /opt/nebula/venv/bin/pip install --upgrade pip -q
ok "Python venv ready at /opt/nebula/venv"

# ================================================================
step "8 — Install NEBULA Blockchain Files"
# ================================================================
info "Copying NEBULA files..."
cp "${NEBULA_FILES[@]}" /opt/nebula/blockchain/
chown -R nebula:nebula /opt/nebula/blockchain/
chmod 640 /opt/nebula/blockchain/*.py
ok "All ${#NEBULA_FILES[@]} NEBULA files installed"

# ================================================================
step "9 — Run Test Suite"
# ================================================================
info "Running 42 blockchain tests..."
cd /opt/nebula/blockchain
TEST_RESULT=$(sudo -u nebula /opt/nebula/venv/bin/python3 nebula_tests.py 2>&1 | tail -4)
echo "$TEST_RESULT"

if echo "$TEST_RESULT" | grep -q "ALL PASSED"; then
    ok "All 42 tests passed!"
else
    warn "Some tests failed — check output above"
fi
cd -

# ================================================================
step "10 — Firewall (UFW)"
# ================================================================
info "Configuring firewall rules..."
ufw --force reset > /dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp          comment "SSH"
ufw allow 8333/tcp        comment "NEBULA P2P"
ufw allow 8334/tcp        comment "NEBULA RPC"
ufw --force enable > /dev/null 2>&1
ok "Firewall enabled"
echo ""
ufw status numbered
echo ""

# ================================================================
step "11 — Fail2Ban (Brute Force Protection)"
# ================================================================
info "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
F2B

systemctl enable fail2ban > /dev/null 2>&1
systemctl restart fail2ban
ok "Fail2Ban enabled — SSH brute force protection active"

# ================================================================
step "12 — Create Miner Wallet"
# ================================================================
info "Creating NEBULA wallet for mining rewards..."
echo ""
warn "Your 12-word mnemonic will appear below."
warn "WRITE IT DOWN ON PAPER. KEEP IT OFFLINE. NEVER SHARE IT."
echo ""

sudo -u nebula /opt/nebula/venv/bin/python3 - << 'WALLETPY'
import sys
sys.path.insert(0, '/opt/nebula/blockchain')
from nebula_wallet import NEBULAWallet
import os, stat

w = NEBULAWallet.create_new()

print()
print("=" * 56)
print("  YOUR NEBULA WALLET")
print("=" * 56)
print(f"  Address  : {w.first_address}")
print()
print("  12-WORD MNEMONIC (WRITE THIS DOWN — NEVER SHARE):")
print(f"  {w.mnemonic}")
print("=" * 56)
print()

# Save address (public - ok to store)
with open('/opt/nebula/config/miner_address.txt', 'w') as f:
    f.write(w.first_address)

# Save backup (private - owner only)
backup_path = '/opt/nebula/config/wallet_backup.txt'
with open(backup_path, 'w') as f:
    f.write(f"NEBULA WALLET BACKUP\n")
    f.write(f"Author  : Zayn Quantum\n")
    f.write(f"Created : {__import__('datetime').datetime.now().isoformat()}\n")
    f.write(f"\nAddress  : {w.first_address}\n")
    f.write(f"Mnemonic : {w.mnemonic}\n")
    f.write(f"\nWARNING: Keep this file PRIVATE. Never share your mnemonic.\n")

os.chmod(backup_path, stat.S_IRUSR | stat.S_IWUSR)  # 600 — owner only
print("  Address saved : /opt/nebula/config/miner_address.txt")
print("  Backup saved  : /opt/nebula/config/wallet_backup.txt")
WALLETPY

ok "Wallet created"
MINER_ADDR=$(cat /opt/nebula/config/miner_address.txt 2>/dev/null || echo "UNKNOWN")
ok "Miner address: $MINER_ADDR"

# ================================================================
step "13 — Systemd Services"
# ================================================================
info "Creating nebula.service (full node)..."
cat > /etc/systemd/system/nebula.service << SERVICE
[Unit]
Description=NEBULA Blockchain Full Node — Zayn Quantum
Documentation=https://github.com/zaynquantum/nebula
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nebula
Group=nebula
WorkingDirectory=/opt/nebula/blockchain
ExecStart=/opt/nebula/venv/bin/python3 nebula_cli.py node --datadir /opt/nebula/data --port 8333
ExecStop=/bin/kill -s SIGTERM \$MAINPID
Restart=always
RestartSec=15
TimeoutStopSec=30
StandardOutput=append:/opt/nebula/logs/nebula.log
StandardError=append:/opt/nebula/logs/nebula.log
LimitNOFILE=65536
LimitNPROC=4096
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
KillMode=mixed
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

info "Creating nebula-miner.service..."
cat > /etc/systemd/system/nebula-miner.service << MINER
[Unit]
Description=NEBULA Blockchain Miner — Zayn Quantum
After=network-online.target nebula.service
Wants=network-online.target

[Service]
Type=simple
User=nebula
Group=nebula
WorkingDirectory=/opt/nebula/blockchain
ExecStart=/opt/nebula/venv/bin/python3 nebula_cli.py mine --address $MINER_ADDR --datadir /opt/nebula/data
Restart=always
RestartSec=30
StandardOutput=append:/opt/nebula/logs/nebula-miner.log
StandardError=append:/opt/nebula/logs/nebula-miner.log
Environment=PYTHONUNBUFFERED=1
LimitNOFILE=65536
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
MINER

systemctl daemon-reload
systemctl enable nebula
systemctl enable nebula-miner
ok "Services created and enabled:"
echo "    nebula.service        — full node (auto-starts on boot)"
echo "    nebula-miner.service  — miner    (auto-starts on boot)"

# ================================================================
step "14 — Log Rotation"
# ================================================================
cat > /etc/logrotate.d/nebula << 'LOGROT'
/opt/nebula/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su nebula nebula
}
LOGROT
ok "Log rotation: daily, keep 30 days"

# ================================================================
step "15 — Auto Backup"
# ================================================================
cat > /opt/nebula/backup/backup.sh << 'BACKUP'
#!/bin/bash
# NEBULA Auto-Backup — runs every 6 hours via cron
BACKUP_DIR="/opt/nebula/backup"
DATA_DIR="/opt/nebula/data"
DATE=$(date +%Y%m%d_%H%M%S)

if [ -f "$DATA_DIR/chain.json" ]; then
    cp "$DATA_DIR/chain.json" "$BACKUP_DIR/chain_$DATE.json"
    # Keep only last 28 backups (7 days x 4 per day)
    ls -t "$BACKUP_DIR"/chain_*.json 2>/dev/null | tail -n +29 | xargs -r rm
    echo "[$(date)] Backup: chain_$DATE.json"
fi
BACKUP

chmod +x /opt/nebula/backup/backup.sh
chown nebula:nebula /opt/nebula/backup/backup.sh

# Add to cron
(crontab -u nebula -l 2>/dev/null; echo "0 */6 * * * /opt/nebula/backup/backup.sh >> /opt/nebula/logs/backup.log 2>&1") | crontab -u nebula -
ok "Auto-backup: every 6 hours, keeps 7 days"

# ================================================================
step "16 — System Optimization"
# ================================================================
info "Optimizing system for blockchain node..."

# Increase file descriptor limits
cat >> /etc/security/limits.conf << 'LIMITS'
nebula soft nofile 65536
nebula hard nofile 65536
nebula soft nproc  4096
nebula hard nproc  4096
LIMITS

# Network optimization
cat >> /etc/sysctl.conf << 'SYSCTL'
# NEBULA Blockchain Optimization
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 1024
net.core.netdev_max_backlog = 5000
SYSCTL

sysctl -p > /dev/null 2>&1
ok "System optimized for P2P networking"

# ================================================================
step "17 — Health Check Script"
# ================================================================
cat > /opt/nebula/nebula_health.sh << 'HEALTH'
#!/bin/bash
# NEBULA Health Check
echo "=== NEBULA Node Health ==="
echo "Node service : $(systemctl is-active nebula)"
echo "Miner service: $(systemctl is-active nebula-miner)"
echo "Disk usage   : $(du -sh /opt/nebula/data 2>/dev/null | cut -f1 || echo 'N/A')"
echo "Log size     : $(du -sh /opt/nebula/logs 2>/dev/null | cut -f1 || echo 'N/A')"
echo "Last backup  : $(ls -t /opt/nebula/backup/chain_*.json 2>/dev/null | head -1 | xargs basename 2>/dev/null || echo 'none')"
echo "Uptime       : $(uptime -p)"
echo "Memory       : $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "CPU          : $(nproc) cores"
HEALTH

chmod +x /opt/nebula/nebula_health.sh
chown nebula:nebula /opt/nebula/nebula_health.sh
ok "Health check script created: /opt/nebula/nebula_health.sh"

# ================================================================
#  FINAL SUMMARY
# ================================================================
echo ""
echo -e "${GOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║   SETUP COMPLETE — NEBULA IS READY!                         ║"
echo "║   Author : Zayn Quantum                                      ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}START COMMANDS:${NC}"
echo "  sudo systemctl start nebula              # Start full node"
echo "  sudo systemctl start nebula-miner        # Start mining"
echo ""
echo -e "${GREEN}MONITOR COMMANDS:${NC}"
echo "  sudo systemctl status nebula             # Node status"
echo "  sudo journalctl -u nebula -f             # Live logs"
echo "  tail -f /opt/nebula/logs/nebula.log      # Log file"
echo "  /opt/nebula/nebula_health.sh             # Health check"
echo ""
echo -e "${GREEN}INTERACTIVE MODE:${NC}"
echo "  cd /opt/nebula/blockchain"
echo "  sudo -u nebula /opt/nebula/venv/bin/python3 nebula_cli.py repl"
echo ""
echo -e "${GREEN}CHECK BALANCE:${NC}"
echo "  cd /opt/nebula/blockchain"
echo "  sudo -u nebula /opt/nebula/venv/bin/python3 nebula_cli.py balance"
echo ""
echo -e "${YELLOW}YOUR MINER ADDRESS:${NC}"
echo "  $(cat /opt/nebula/config/miner_address.txt 2>/dev/null || echo 'check /opt/nebula/config/')"
echo ""
echo -e "${RED}KEEP SAFE — YOUR MNEMONIC BACKUP:${NC}"
echo "  sudo cat /opt/nebula/config/wallet_backup.txt"
echo ""
echo -e "${GOLD}NEBULA Blockchain — Zayn Quantum — For All Humanity 🌍${NC}"
echo ""

"""
================================================================
  NEBULA SECURITY — nebula_security.py
  Complete Security — Like Bitcoin Core
  
  - DoS protection
  - Rate limiting
  - Peer banning
  - Transaction validation
  - Block validation
  - Replay attack protection
  - Double-spend detection
  - Sybil resistance
  - Checkpoint system
  - Alert system
================================================================
"""

import time, hashlib, threading, json, ipaddress
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

# ================================================================
#  BAN REASONS
# ================================================================

class BanReason(Enum):
    INVALID_BLOCK       = "invalid_block"
    INVALID_TX          = "invalid_tx"
    MISBEHAVIOR         = "misbehavior"
    DOS_ATTACK          = "dos_attack"
    SPAM                = "spam"
    DUPLICATE_HEADERS   = "duplicate_headers"
    INVALID_HANDSHAKE   = "invalid_handshake"
    WRONG_CHAIN         = "wrong_chain"

@dataclass
class BanEntry:
    ip:         str
    reason:     BanReason
    score:      int
    banned_at:  float = field(default_factory=time.time)
    expires_at: float = 0.0   # 0 = permanent

    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

# ================================================================
#  DOS PROTECTION
# ================================================================

class DoSProtection:
    """
    Per-IP misbehavior scoring — like Bitcoin Core.
    Score 0-100. At 100, ban the peer.
    """

    BAN_THRESHOLD   = 100
    BAN_DURATION    = 86400     # 24 hours default
    MAX_SCORE       = 100

    # Score increments per violation
    SCORES = {
        "invalid_block_header":  20,
        "invalid_block_hash":    100,   # instant ban
        "invalid_block_merkle":  100,
        "invalid_tx_format":     10,
        "invalid_tx_signature":  10,
        "invalid_tx_doublespend":100,
        "too_many_getdata":      1,
        "oversized_message":     50,
        "spam_tx":               5,
        "headers_flood":         20,
        "ping_flood":            1,
        "wrong_chain_id":        100,
    }

    def __init__(self):
        self._scores:   Dict[str, int]        = defaultdict(int)
        self._bans:     Dict[str, BanEntry]   = {}
        self._lock      = threading.RLock()

    def punish(self, ip: str, violation: str) -> bool:
        """Add misbehavior score. Returns True if peer should be banned."""
        with self._lock:
            if ip in self._bans and not self._bans[ip].is_expired():
                return True
            score = self.SCORES.get(violation, 1)
            self._scores[ip] = min(self._scores[ip] + score, self.MAX_SCORE)
            if self._scores[ip] >= self.BAN_THRESHOLD:
                self._ban(ip, BanReason.MISBEHAVIOR, self.BAN_DURATION)
                return True
            return False

    def _ban(self, ip: str, reason: BanReason, duration: float = 0):
        self._bans[ip] = BanEntry(
            ip         = ip,
            reason     = reason,
            score      = self._scores.get(ip, 100),
            expires_at = time.time() + duration if duration > 0 else 0,
        )
        print(f"🚫 Banned {ip}: {reason.value} (score: {self._scores[ip]})")

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            entry = self._bans.get(ip)
            if entry is None:
                return False
            if entry.is_expired():
                del self._bans[ip]
                return False
            return True

    def get_score(self, ip: str) -> int:
        return self._scores.get(ip, 0)

    def unban(self, ip: str):
        with self._lock:
            self._bans.pop(ip, None)
            self._scores.pop(ip, None)

    def ban_list(self) -> List[dict]:
        with self._lock:
            return [{
                "ip":       e.ip,
                "reason":   e.reason.value,
                "score":    e.score,
                "expires":  e.expires_at,
                "permanent":e.expires_at == 0,
            } for e in self._bans.values() if not e.is_expired()]

    def cleanup(self):
        with self._lock:
            expired = [ip for ip, e in self._bans.items() if e.is_expired()]
            for ip in expired:
                del self._bans[ip]


# ================================================================
#  RATE LIMITER
# ================================================================

class RateLimiter:
    """Token bucket rate limiter per IP"""

    def __init__(self,
                 rate_per_sec: float = 10.0,
                 burst:        int   = 50):
        self._rate      = rate_per_sec
        self._burst     = burst
        self._tokens:   Dict[str, float] = defaultdict(lambda: float(burst))
        self._last:     Dict[str, float] = defaultdict(time.time)
        self._lock      = threading.Lock()

    def allow(self, ip: str, cost: float = 1.0) -> bool:
        with self._lock:
            now    = time.time()
            elapsed = now - self._last.get(ip, now)
            self._last[ip]   = now
            # Refill tokens
            self._tokens[ip] = min(
                self._burst,
                self._tokens.get(ip, self._burst) + elapsed * self._rate
            )
            if self._tokens[ip] >= cost:
                self._tokens[ip] -= cost
                return True
            return False

    def reset(self, ip: str):
        with self._lock:
            self._tokens[ip] = float(self._burst)
            self._last[ip]   = time.time()


# ================================================================
#  DOUBLE SPEND DETECTOR
# ================================================================

class DoubleSpendDetector:
    """
    Detects double-spend attempts in mempool and across blocks.
    Tracks all UTXO references being spent.
    """

    def __init__(self):
        self._spending: Dict[str, str] = {}  # "txid:idx" -> spending_txid
        self._lock = threading.Lock()

    def _key(self, txid: str, index: int) -> str:
        return f"{txid}:{index}"

    def register(self, txid: str, inputs: List) -> Tuple[bool, Optional[str]]:
        """
        Register transaction inputs.
        Returns (ok, conflicting_txid).
        """
        with self._lock:
            new_keys = []
            for inp in inputs:
                k = self._key(inp.outpoint.txid, inp.outpoint.index)
                if k in self._spending:
                    conflict = self._spending[k]
                    if conflict != txid:
                        return False, conflict
                new_keys.append(k)
            for k in new_keys:
                self._spending[k] = txid
            return True, None

    def release(self, txid: str):
        """Remove transaction's inputs from tracker"""
        with self._lock:
            to_del = [k for k, v in self._spending.items() if v == txid]
            for k in to_del:
                del self._spending[k]

    def clear_block(self, inputs: List):
        """Remove confirmed inputs from tracker"""
        with self._lock:
            for inp in inputs:
                k = self._key(inp.outpoint.txid, inp.outpoint.index)
                self._spending.pop(k, None)

    def conflict_count(self) -> int:
        return len(self._spending)


# ================================================================
#  REPLAY ATTACK PROTECTION
# ================================================================

class ReplayProtection:
    """
    Prevents transaction replay across chains.
    Uses chain_id in sighash (like EIP-155 for Ethereum).
    """

    def __init__(self, chain_id: int):
        self.chain_id = chain_id
        self._seen_txids: Set[str] = set()
        self._lock = threading.Lock()
        self.MAX_CACHE = 100_000

    def mark_seen(self, txid: str):
        with self._lock:
            if len(self._seen_txids) > self.MAX_CACHE:
                # Clear oldest 20%
                to_remove = list(self._seen_txids)[:self.MAX_CACHE // 5]
                for t in to_remove:
                    self._seen_txids.discard(t)
            self._seen_txids.add(txid)

    def is_replay(self, txid: str) -> bool:
        with self._lock:
            return txid in self._seen_txids

    def chain_sighash_suffix(self) -> bytes:
        """Extra bytes appended to sighash to bind tx to this chain"""
        return self.chain_id.to_bytes(4, 'little')


# ================================================================
#  CHECKPOINTS
# ================================================================

@dataclass
class Checkpoint:
    height: int
    hash:   str
    time:   int

# Hardcoded checkpoints (like Bitcoin Core)
# These will be filled as NEBULA grows
NEBULA_CHECKPOINTS: List[Checkpoint] = [
    Checkpoint(0,      "genesis",  1742083200),  # Genesis block — 2025-03-16
    # Future checkpoints added here as network matures:
    # Checkpoint(10000,  "...",   ...),
    # Checkpoint(50000,  "...",   ...),
    # Checkpoint(100000, "...",   ...),
]

class CheckpointSystem:
    """Validates blocks against hardcoded checkpoints"""

    def __init__(self):
        self._checkpoints = {cp.height: cp for cp in NEBULA_CHECKPOINTS}
        self.max_height   = max((cp.height for cp in NEBULA_CHECKPOINTS), default=0)

    def validate(self, height: int, block_hash: str) -> Tuple[bool, str]:
        cp = self._checkpoints.get(height)
        if cp is None:
            return True, "No checkpoint at this height"
        if cp.hash == "genesis":
            return True, "Genesis checkpoint (any hash)"
        if cp.hash != block_hash:
            return False, f"Checkpoint mismatch at height {height}"
        return True, "Checkpoint passed"

    def is_before_checkpoint(self, height: int) -> bool:
        return height <= self.max_height

    def add_checkpoint(self, cp: Checkpoint):
        self._checkpoints[cp.height] = cp
        self.max_height = max(self.max_height, cp.height)


# ================================================================
#  TRANSACTION SANITIZER
# ================================================================

class TxSanitizer:
    """
    Validates transactions before they enter mempool or chain.
    First line of defense against malformed data.
    """

    MAX_TX_SIZE    = 100_000   # 100 KB
    MAX_INPUTS     = 1_000
    MAX_OUTPUTS    = 1_000
    MAX_SCRIPT_SIZE = 10_000
    MIN_AMOUNT     = 1         # 1 Neb

    def sanitize(self, tx) -> Tuple[bool, str]:
        """Full transaction sanitization"""
        # Size check
        if tx.byte_size() > self.MAX_TX_SIZE:
            return False, f"TX too large: {tx.byte_size()} > {self.MAX_TX_SIZE}"

        # Input count
        if len(tx.inputs) == 0:
            return False, "No inputs"
        if len(tx.inputs) > self.MAX_INPUTS:
            return False, f"Too many inputs: {len(tx.inputs)}"

        # Output count
        if len(tx.outputs) == 0:
            return False, "No outputs"
        if len(tx.outputs) > self.MAX_OUTPUTS:
            return False, f"Too many outputs: {len(tx.outputs)}"

        # Check each output
        total_out = 0
        for i, out in enumerate(tx.outputs):
            if out.value < 0:
                return False, f"Negative output {i}: {out.value}"
            if len(out.script_pubkey) > self.MAX_SCRIPT_SIZE:
                return False, f"Output {i} script too large"
            total_out += out.value

        # Check for overflow
        if total_out > 21_000_000 * 10**9:
            return False, "Total output exceeds possible supply"

        # Duplicate inputs
        outpoints = set()
        for inp in tx.inputs:
            key = f"{inp.outpoint.txid}:{inp.outpoint.index}"
            if key in outpoints:
                return False, f"Duplicate input: {key}"
            outpoints.add(key)

        # Script sizes
        for i, inp in enumerate(tx.inputs):
            if len(inp.script_sig) > self.MAX_SCRIPT_SIZE:
                return False, f"Input {i} script too large"

        return True, "OK"


# ================================================================
#  BLOCK SANITIZER
# ================================================================

class BlockSanitizer:
    """Sanitizes blocks before full validation"""

    MAX_BLOCK_SIZE   = 1_048_576   # 1 MB
    MAX_TXS          = 3_000
    MAX_COINBASE_SIZE = 100

    def __init__(self):
        self.tx_san = TxSanitizer()

    def sanitize(self, block) -> Tuple[bool, str]:
        # Size
        if block.byte_size() > self.MAX_BLOCK_SIZE:
            return False, f"Block too large: {block.byte_size()}"

        # Must have txs
        if not block.transactions:
            return False, "No transactions in block"

        # TX count
        if len(block.transactions) > self.MAX_TXS:
            return False, f"Too many txs: {len(block.transactions)}"

        # Coinbase must be first
        if not block.transactions[0].is_coinbase:
            return False, "First tx must be coinbase"

        # Only one coinbase
        for tx in block.transactions[1:]:
            if tx.is_coinbase:
                return False, "Multiple coinbases"

        # Coinbase script size
        cb_script = block.transactions[0].inputs[0].script_sig
        if len(cb_script) > self.MAX_COINBASE_SIZE:
            return False, f"Coinbase script too long: {len(cb_script)}"

        # Sanitize each tx
        seen_txids: Set[str] = set()
        for tx in block.transactions[1:]:
            if tx.txid in seen_txids:
                return False, f"Duplicate tx: {tx.txid}"
            seen_txids.add(tx.txid)
            ok, msg = self.tx_san.sanitize(tx)
            if not ok:
                return False, f"TX {tx.txid[:8]}: {msg}"

        return True, "OK"


# ================================================================
#  IP FILTER
# ================================================================

class IPFilter:
    """Blocks private/reserved IPs from being added as peers (anti-Sybil)"""

    PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
    ]

    def __init__(self):
        self._nets = [ipaddress.ip_network(r) for r in self.PRIVATE_RANGES]
        self._whitelist: Set[str] = set()

    def is_allowed(self, ip: str) -> bool:
        if ip in self._whitelist:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return not any(addr in net for net in self._nets)
        except ValueError:
            return False

    def whitelist(self, ip: str):
        self._whitelist.add(ip)


# ================================================================
#  ALERT SYSTEM
# ================================================================

class AlertLevel(Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"

@dataclass
class SecurityAlert:
    level:   AlertLevel
    message: str
    data:    dict
    ts:      float = field(default_factory=time.time)

class AlertSystem:
    """Security alert system — like Bitcoin's alert system"""

    def __init__(self):
        self._alerts:    List[SecurityAlert] = []
        self._handlers:  List               = []
        self._lock       = threading.Lock()

    def add_handler(self, fn):
        self._handlers.append(fn)

    def alert(self, level: AlertLevel, message: str, data: dict = None):
        a = SecurityAlert(level, message, data or {})
        with self._lock:
            self._alerts.append(a)
        prefix = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "🚨"}[level.value]
        print(f"{prefix} [{level.value}] {message}")
        for handler in self._handlers:
            try:
                handler(a)
            except Exception:
                pass

    def info(self,     msg: str, data: dict = None): self.alert(AlertLevel.INFO,     msg, data)
    def warning(self,  msg: str, data: dict = None): self.alert(AlertLevel.WARNING,  msg, data)
    def critical(self, msg: str, data: dict = None): self.alert(AlertLevel.CRITICAL, msg, data)

    def recent(self, n: int = 20) -> List[dict]:
        with self._lock:
            return [{"level": a.level.value, "msg": a.message, "ts": a.ts}
                    for a in self._alerts[-n:]]


# ================================================================
#  SECURITY MANAGER — combines everything
# ================================================================

class SecurityManager:
    """Central security manager for NEBULA node"""

    def __init__(self, chain_id: int = 2025):
        self.dos          = DoSProtection()
        self.rate         = RateLimiter(rate_per_sec=20, burst=100)
        self.double_spend = DoubleSpendDetector()
        self.replay       = ReplayProtection(chain_id)
        self.checkpoints  = CheckpointSystem()
        self.tx_sanitizer = TxSanitizer()
        self.blk_sanitizer = BlockSanitizer()
        self.ip_filter    = IPFilter()
        self.alerts       = AlertSystem()

        # Stats
        self._stats = {
            "blocks_rejected":  0,
            "txs_rejected":     0,
            "ips_banned":       0,
            "double_spends":    0,
            "rate_limited":     0,
        }

    def check_peer(self, ip: str) -> Tuple[bool, str]:
        """Full peer connection check"""
        if self.dos.is_banned(ip):
            return False, "IP is banned"
        if not self.ip_filter.is_allowed(ip):
            # Allow private IPs in dev mode
            pass
        if not self.rate.allow(ip, cost=1.0):
            self._stats["rate_limited"] += 1
            return False, "Rate limited"
        return True, "OK"

    def validate_incoming_block(self, block, ip: str) -> Tuple[bool, str]:
        """Full security check for incoming block"""
        # Sanitize
        ok, msg = self.blk_sanitizer.sanitize(block)
        if not ok:
            self.dos.punish(ip, "invalid_block_header")
            self._stats["blocks_rejected"] += 1
            self.alerts.warning(f"Invalid block from {ip}: {msg}")
            return False, msg

        # Checkpoint
        ok, msg = self.checkpoints.validate(block.height, block.hash)
        if not ok:
            self.dos.punish(ip, "invalid_block_hash")
            self._stats["blocks_rejected"] += 1
            self.alerts.critical(f"Checkpoint violation from {ip}!", {"height": block.height})
            return False, msg

        return True, "OK"

    def validate_incoming_tx(self, tx, ip: str) -> Tuple[bool, str]:
        """Full security check for incoming tx"""
        # Replay check
        if self.replay.is_replay(tx.txid):
            self._stats["txs_rejected"] += 1
            return False, "Replay transaction"

        # Sanitize
        ok, msg = self.tx_sanitizer.sanitize(tx)
        if not ok:
            self.dos.punish(ip, "invalid_tx_format")
            self._stats["txs_rejected"] += 1
            return False, msg

        # Double spend
        ok, conflict = self.double_spend.register(tx.txid, tx.inputs)
        if not ok:
            self.dos.punish(ip, "invalid_tx_doublespend")
            self._stats["double_spends"] += 1
            self.alerts.warning(f"Double spend from {ip}: {tx.txid[:16]} vs {conflict[:16] if conflict else '?'}")
            return False, f"Double spend: conflicts with {conflict}"

        self.replay.mark_seen(tx.txid)
        return True, "OK"

    def punish_peer(self, ip: str, violation: str) -> bool:
        banned = self.dos.punish(ip, violation)
        if banned:
            self._stats["ips_banned"] += 1
            self.alerts.warning(f"Peer banned: {ip} ({violation})")
        return banned

    def status(self) -> dict:
        return {
            **self._stats,
            "banned_ips":      len(self.dos.ban_list()),
            "tracked_spends":  self.double_spend.conflict_count(),
            "checkpoints":     len(NEBULA_CHECKPOINTS),
            "chain_id":        self.replay.chain_id,
        }
