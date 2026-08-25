# Author:   Bushy <contact@bushy.dev>
# Version:  v1.1.3
# Modified: 2026-05-28
#
# sign_pbo.py: sign a hemtt-built PBO with a stable authority name.
# Algorithm derived from hemtt/libs/signing (BrettMayson/HEMTT, GPLv2).
# Bikey/bisign format: RSA 1024-bit, little-endian integers, PKCS#1v1.5 SHA-1.
# Upstream: https://github.com/bearmeister/sign-pbo

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# RSA key generation  (requires cryptography package)
# ---------------------------------------------------------------------------

def _load_rsa2_biprivatekey(data: bytes) -> tuple[int, int, int, int]:
    """Parse a RSA2 CRT private key (DS utils / DayZ Tools .biprivatekey).

    Layout: authority\x00 + 4-byte length + 8-byte magic + b'RSA2' +
            4-byte key_bits + 4-byte e + key_bytes n +
            half p + half q + half dp + half dq + half qinv + key_bytes d
    Returns (n, e, d, key_bits).
    """
    off = data.index(b'\x00') + 1   # skip authority + null
    off += 4 + 8                     # length field + magic
    if data[off:off + 4] != b'RSA2':
        raise ValueError(f'Expected RSA2 tag, got {data[off:off+4]!r}')
    off += 4
    key_bits = struct.unpack_from('<I', data, off)[0]; off += 4
    key_bytes = key_bits // 8
    half = key_bytes // 2
    e = struct.unpack_from('<I', data, off)[0]; off += 4
    n    = int.from_bytes(data[off:off + key_bytes], 'little'); off += key_bytes
    off += half * 4   # skip p, q, dp, dq
    off += half       # skip qinv (=half)
    d    = int.from_bytes(data[off:off + key_bytes], 'little')
    return n, e, d, key_bits


def _load_or_generate_key(key_path: Path) -> tuple[int, int, int, int]:
    """Return (n, e, d, key_bits).

    Accepts three key sources (checked in order):
    1. <key_path> with .biprivatekey suffix  - RSA2 CRT format (DS utils)
    2. <key_path> with .privatekey suffix    - this script's own compact format
    3. Neither exists                        - generate a new key and save as .privatekey

    The caller should pass the .privatekey path; for .biprivatekey pass that path directly.
    """
    if key_path.exists():
        data = key_path.read_bytes()
        if key_path.suffix == '.biprivatekey':
            return _load_rsa2_biprivatekey(data)
        # Own compact format: 4 bytes key_bits LE, then n/e/d prefixed by 4-byte length
        offset = 0
        key_bits = struct.unpack_from('<I', data, offset)[0]; offset += 4
        n = _read_le_int(data, offset); offset += 4 + key_bits // 8
        e = _read_le_int(data, offset); offset += 4 + 4
        d = _read_le_int(data, offset)
        return n, e, d, key_bits

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend(),
    )
    pub = private_key.public_key().public_numbers()
    priv = private_key.private_numbers()
    n, e, d = pub.n, pub.e, priv.d
    key_bits = 1024

    out = bytearray()
    out += struct.pack('<I', key_bits)
    _write_le_int(out, n, key_bits // 8)
    _write_le_int(out, e, 4)
    _write_le_int(out, d, key_bits // 8)
    key_path.write_bytes(bytes(out))
    return n, e, d, key_bits


def _read_le_int(data: bytes, offset: int) -> int:
    length = struct.unpack_from('<I', data, offset)[0]
    raw = data[offset + 4: offset + 4 + length]
    return int.from_bytes(raw, 'little')


def _write_le_int(buf: bytearray, value: int, size: int) -> None:
    raw = value.to_bytes(size, 'little')
    buf += struct.pack('<I', size)
    buf += raw


# ---------------------------------------------------------------------------
# Bikey serialisation
# ---------------------------------------------------------------------------

def write_bikey(authority: str, n: int, e: int, key_bits: int) -> bytes:
    """Serialise a public key blob to bytes (the .bikey format)."""
    buf = bytearray()
    buf += authority.encode() + b'\x00'
    buf += struct.pack('<I', key_bits // 8 + 20)
    buf += b'\x06\x02\x00\x00\x00\x24\x00\x00'
    buf += b'RSA1'
    buf += struct.pack('<I', key_bits)
    buf += e.to_bytes(4, 'little')
    buf += n.to_bytes(key_bits // 8, 'little')
    return bytes(buf)


# ---------------------------------------------------------------------------
# PBO parsing - extract the data needed for the three hashes
# ---------------------------------------------------------------------------

def _read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.index(b'\x00', offset)
    return data[offset:end].decode('utf-8', errors='replace'), end + 1


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from('<I', data, offset)[0], offset + 4


class PboFile:
    def __init__(self, filename: str, packing_method: int,
                 original_size: int, data_size: int, data_offset: int):
        self.filename = filename
        self.packing_method = packing_method
        self.original_size = original_size
        self.data_size = data_size
        self.data_offset = data_offset


def parse_pbo(pbo_bytes: bytes) -> tuple[dict, list[PboFile], bytes]:
    """Return (properties, files, raw_header_bytes_for_gen_checksum)."""
    offset = 0
    properties: dict[str, str] = {}
    files: list[PboFile] = []

    # Header section: entries with packing_method, original_size,
    # reserved, timestamp, data_size. Special 'vers' entry first.
    header_start = 0

    # First entry filename - for the vers header it's empty
    first_filename, offset = _read_cstring(pbo_bytes, offset)

    # If first entry is vers entry (empty filename, packing=0x56657273)
    packing, offset = _read_u32(pbo_bytes, offset)
    if packing == 0x56657273:  # 'Vers' magic
        # Skip the 4 reserved fields
        for _ in range(4):
            _, offset = _read_u32(pbo_bytes, offset)
        # Read properties until empty key
        while True:
            key, offset = _read_cstring(pbo_bytes, offset)
            if not key:
                break
            value, offset = _read_cstring(pbo_bytes, offset)
            properties[key] = value
    else:
        # No vers header - put back the first entry
        # (we already consumed filename + packing method)
        orig_size, offset = _read_u32(pbo_bytes, offset)
        _reserved, offset = _read_u32(pbo_bytes, offset)
        _timestamp, offset = _read_u32(pbo_bytes, offset)
        data_size, offset = _read_u32(pbo_bytes, offset)
        if first_filename:
            files.append(PboFile(first_filename, packing, orig_size,
                                 data_size, -1))  # offset filled later

    # Read remaining file headers until empty sentinel
    while True:
        filename, offset = _read_cstring(pbo_bytes, offset)
        if not filename:
            # Read the 5 u32s of the sentinel and stop
            for _ in range(5):
                _, offset = _read_u32(pbo_bytes, offset)
            break
        packing2, offset = _read_u32(pbo_bytes, offset)
        orig_size, offset = _read_u32(pbo_bytes, offset)
        _reserved, offset = _read_u32(pbo_bytes, offset)
        _timestamp, offset = _read_u32(pbo_bytes, offset)
        data_size, offset = _read_u32(pbo_bytes, offset)
        files.append(PboFile(filename, packing2, orig_size, data_size, -1))

    # Record end of header section (used for gen_checksum)
    header_end = offset

    # Now fill in data offsets
    data_offset = offset
    for f in files:
        f.data_offset = data_offset
        data_offset += f.data_size

    raw_headers = pbo_bytes[header_start:header_end]
    return properties, files, raw_headers


def _file_data(pbo_bytes: bytes, f: PboFile) -> bytes:
    return pbo_bytes[f.data_offset: f.data_offset + f.data_size]


# ---------------------------------------------------------------------------
# gen_checksum - SHA-1 over PBO headers + file data (sorted)
# ---------------------------------------------------------------------------

def gen_checksum(properties: dict, files: list[PboFile],
                 raw_headers: bytes, pbo_bytes: bytes) -> bytes:
    """Recompute the PBO checksum the same way hemtt does."""
    # hemtt builds a buffer: vers_header + prefix property + other properties
    # + empty key + all file headers (sorted by filename) + sentinel header
    # then SHA-1(buffer + all file data in sorted order).
    #
    # Since we already have raw_headers from the actual PBO which was built
    # by hemtt, we can use those directly - they ARE the correct header bytes.
    hasher = hashlib.sha1()
    hasher.update(raw_headers)
    for f in sorted(files, key=lambda x: x.filename.lower()):
        hasher.update(_file_data(pbo_bytes, f))
    return hasher.digest()


def hash_filenames(files: list[PboFile], pbo_bytes: bytes) -> bytes:
    """SHA-1 of all non-empty file names (lowercased, backslash-normalised)."""
    hasher = hashlib.sha1()
    for f in sorted(files, key=lambda x: x.filename.lower()):
        data = _file_data(pbo_bytes, f)
        if not data:
            continue
        name = f.filename.replace('/', '\\').lower()
        hasher.update(name.encode())
    return hasher.digest()


# V3 extension whitelist.
# Arma 3 / hemtt omit .c - DayZ engine and DS utils include it (EnforceScript).
# Missing .c causes hash3 mismatch -> engine kicks clients at verifySignatures=2.
_V3_EXTS = {'.bikb', '.c', '.cfg', '.ext', '.fsm', '.h', '.hpp',
            '.inc', '.sqf', '.sqfc', '.sqm', '.sqs'}


def hash_files_v3(files: list[PboFile], pbo_bytes: bytes) -> bytes:
    """SHA-1 of file data for V3-relevant extensions only."""
    hasher = hashlib.sha1()
    nothing = True
    for f in sorted(files, key=lambda x: x.filename.lower()):
        ext = Path(f.filename).suffix.lower()
        if ext not in _V3_EXTS:
            continue
        nothing = False
        hasher.update(_file_data(pbo_bytes, f))
    if nothing:
        hasher.update(b'gnihton')
    return hasher.digest()


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 padding + signing
# ---------------------------------------------------------------------------

def pad_hash(sha1_hash: bytes, key_bytes: int) -> int:
    """Return the padded hash as a big-endian integer (as hemtt does)."""
    # Format: 0x00 0x01 0xFF...FF 0x00 <SHA1-OID> <hash>
    oid = bytes([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
                 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14])
    suffix = oid + sha1_hash          # 15 + 20 = 35 bytes
    prefix = b'\x00\x01'              # 2 bytes
    padding = b'\xff' * (key_bytes - 2 - 1 - len(suffix))  # FF padding
    padded = prefix + padding + b'\x00' + suffix
    assert len(padded) == key_bytes
    return int.from_bytes(padded, 'big')  # big-endian integer (hemtt uses from_be_slice)


def rsa_sign(hash_int: int, d: int, n: int) -> int:
    """sig = hash^d mod n  (raw RSA private-key operation)."""
    return pow(hash_int, d, n)


# ---------------------------------------------------------------------------
# Bisign serialisation
# ---------------------------------------------------------------------------

def write_bisign(authority: str, n: int, e: int, key_bits: int,
                 sig1: int, sig2: int, sig3: int) -> bytes:
    """Serialise a signature blob to bytes (the .bisign format)."""
    key_bytes = key_bits // 8
    buf = bytearray()
    buf += authority.encode() + b'\x00'
    buf += struct.pack('<I', key_bytes + 20)
    buf += b'\x06\x02\x00\x00\x00\x24\x00\x00'
    buf += b'RSA1'
    buf += struct.pack('<I', key_bits)
    buf += e.to_bytes(4, 'little')
    buf += n.to_bytes(key_bytes, 'little')
    buf += struct.pack('<I', key_bytes)
    buf += sig1.to_bytes(key_bytes, 'little')
    buf += struct.pack('<I', 3)          # V3
    buf += struct.pack('<I', key_bytes)
    buf += sig2.to_bytes(key_bytes, 'little')
    buf += struct.pack('<I', key_bytes)
    buf += sig3.to_bytes(key_bytes, 'little')
    return bytes(buf)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def sign(pbo_path: Path, authority: str, key_dir: Path) -> None:
    key_dir.mkdir(parents=True, exist_ok=True)
    bikey_path = key_dir / f'{authority}.bikey'

    # Prefer .biprivatekey (DS utils / DayZ Tools) over .privatekey (this script)
    biprivate = key_dir / f'{authority}.biprivatekey'
    key_path  = biprivate if biprivate.exists() else key_dir / f'{authority}.privatekey'

    n, e, d, key_bits = _load_or_generate_key(key_path)

    # Write bikey
    bikey_data = write_bikey(authority, n, e, key_bits)
    bikey_path.write_bytes(bikey_data)
    print(f'bikey   -> {bikey_path}  ({len(bikey_data)} bytes)')

    # Parse PBO
    pbo_bytes = pbo_path.read_bytes()
    properties, files, raw_headers = parse_pbo(pbo_bytes)

    key_bytes = key_bits // 8

    # Hash 1: gen_checksum
    h1 = gen_checksum(properties, files, raw_headers, pbo_bytes)

    # Hash 2: SHA-1(h1 + hash_filenames + prefix + '\')
    prefix = properties.get('prefix', '')
    fn_hash = hash_filenames(files, pbo_bytes)
    hasher = hashlib.sha1()
    hasher.update(h1)
    hasher.update(fn_hash)
    hasher.update(prefix.encode())
    if prefix and not prefix.endswith('\\'):
        hasher.update(b'\\')
    h2 = hasher.digest()

    # Hash 3: SHA-1(hash_files_v3 + hash_filenames + prefix + '\')
    fh = hash_files_v3(files, pbo_bytes)
    hasher = hashlib.sha1()
    hasher.update(fh)
    hasher.update(fn_hash)
    hasher.update(prefix.encode())
    if prefix and not prefix.endswith('\\'):
        hasher.update(b'\\')
    h3 = hasher.digest()

    # Pad and sign
    sig1 = rsa_sign(pad_hash(h1, key_bytes), d, n)
    sig2 = rsa_sign(pad_hash(h2, key_bytes), d, n)
    sig3 = rsa_sign(pad_hash(h3, key_bytes), d, n)

    # Write bisign
    bisign_data = write_bisign(authority, n, e, key_bits, sig1, sig2, sig3)
    bisign_path = pbo_path.parent / f'{pbo_path.name}.{authority}.bisign'
    bisign_path.write_bytes(bisign_data)
    print(f'bisign  -> {bisign_path}  ({len(bisign_data)} bytes)')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Sign a PBO with a stable authority name.')
    parser.add_argument('pbo', type=Path, help='Path to the .pbo file')
    parser.add_argument('authority', help='Authority name (becomes the key/sig filename)')
    parser.add_argument('--key-dir', type=Path, default=Path('.signing'),
                        help='Directory to store/load the key pair (default: .signing/)')
    args = parser.parse_args()

    if not args.pbo.exists():
        sys.exit(f'error: PBO not found: {args.pbo}')

    sign(args.pbo, args.authority, args.key_dir)
    print('done.')


if __name__ == '__main__':
    main()
