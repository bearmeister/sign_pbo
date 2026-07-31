# sign-pbo

**v1.1.3**

A small Python utility that signs DayZ PBOs with a stable authority name,
producing a `.bisign` file that satisfies `verifySignatures=2` on a DayZ
server.

The reason this exists: [hemtt](https://github.com/BrettMayson/HEMTT) is the
modern DayZ/Arma build tool, but its signer is written for **Arma 3**
semantics. Arma 3 omits `.c` files from the V3 hash; DayZ does not. A PBO
signed by hemtt and shipped to a DayZ server will pass `verifySignatures=1`
but fail under `=2` because the engine recomputes hash3 including `.c` files
and gets a different digest.

`sign_pbo` reimplements the V3 signing algorithm with the **DayZ extension
set** (including `.c`), so the signature matches what the DayZ engine
expects.

## Install

No PyPI release yet, so install directly from the tagged GitHub archive:

```bash
pip install https://github.com/bearmeister/sign-pbo/archive/refs/tags/v1.1.3.zip
```

Works on any environment with `pip` and Python 3.10+; no `git` binary
required. Pulls in `cryptography` automatically.

If you already have `git` installed:

```bash
pip install git+https://github.com/bearmeister/sign-pbo@v1.1.3
```

Or from a local clone:

```bash
git clone https://github.com/bearmeister/sign-pbo
cd sign-pbo
pip install -e .
```

## Usage

```bash
sign-pbo path/to/your.pbo MyAuthority
```

This will:

1. Look for `MyAuthority.biprivatekey` or `MyAuthority.privatekey` in `.signing/`.
2. If neither exists, generate a fresh RSA-1024 keypair and save it as `.signing/MyAuthority.privatekey`.
3. Write `.signing/MyAuthority.bikey` (the public key: drop this on your server's `keys/` directory).
4. Write `path/to/your.pbo.MyAuthority.bisign` next to the PBO.

Use `--key-dir` to point at a different directory:

```bash
sign-pbo path/to/your.pbo MyAuthority --key-dir ~/.dayz-keys
```

## Key formats

Two private-key formats are accepted in `--key-dir`:

| Extension | Format | Source |
|-----------|--------|--------|
| `.biprivatekey` | RSA2 CRT (n, e, d, p, q, dp, dq, qinv) | DS Utils, DayZ Tools, Mikero's `DsSignFile` |
| `.privatekey` | Compact (n, e, d only) | This tool (auto-generated) |

If you already have a `.biprivatekey` from DayZ Tools, drop it into the key
directory and `sign_pbo` will use it. The public-key portion is re-emitted
as `.bikey` on each run, so you never need to maintain that separately.

`.biprivatekey` is preferred over `.privatekey` when both exist for the same
authority.

## The V3 `.c` quirk

V3 signatures (`bisign` version field = 3) include three hashes:

| Hash | Covers |
|------|--------|
| `hash1` | Full PBO content (every file, every byte) |
| `hash2` | Filenames + properties |
| `hash3` | A whitelisted subset of file extensions (script/config files) |

The hash3 extension whitelist is where Arma 3 and DayZ disagree:

| Engine | hash3 includes `.c`? |
|--------|----------------------|
| Arma 3 | **No** (`.c` is C source; Arma uses `.sqf`) |
| DayZ | **Yes** (`.c` is EnforceScript: the entire scripting language) |

[armake2](https://github.com/KoffeinFlummi/armake2) and hemtt both follow
Arma 3's convention. For DayZ this is wrong: every mission and mod ships
`.c` files and excluding them from hash3 means the engine kicks clients
whenever `verifySignatures=2` is enabled.

The fix is mechanically trivial (add `.c` to the V3 extension set) but no
mainstream signer does it. This tool does.

The full DayZ V3 set used here:

```
.bikb  .c     .cfg   .ext   .fsm   .h     .hpp
.inc   .sqf   .sqfc  .sqm   .sqs
```

## Tested against

The output `.bisign` has been verified to:

- Round-trip RSA-verify with the emitted public key (CI test).
- Pass `verifySignatures=2` on a stock DayZ 1.29.162510 dedicated server.
- Validate against DayZ Tools' `DsCheckSignatures.exe` (manual check).

## Library use

The CLI is a thin wrapper around `sign_pbo.signer.sign()`:

```python
from pathlib import Path
from sign_pbo import sign

bisign_path = sign(
    pbo_path=Path("MyMod.pbo"),
    authority="MyAuthority",
    key_dir=Path(".signing"),
)
print(f"wrote {bisign_path}")
```

## Credits

The signing algorithm is derived from [hemtt](https://github.com/BrettMayson/HEMTT)'s
`libs/signing` (GPL-2.0). The PBO format is well-documented in `armake2` and
Mikero's tools.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

This is a derivative work of hemtt's signing logic (GPLv2). GPLv3 is
compatible with GPLv2-or-later code; if you are vendoring this into a
pure-GPLv2 project, use the v2 branch of the algorithm directly from hemtt
instead.
