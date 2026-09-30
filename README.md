# 010-keygen

Analysis of the 010 registration algorithm and a keygen.

## Analysis

Key functions:

| Purpose | Address |
|---|---|
| Registration dialog OK handler (result-code dispatch) | `sub_100369C80` |
| Inner verifier | `sub_100105E10` |
| Translator (result-code mapping) | `sub_100105CB0` |
| hash | `sub_10019C330` |
| Version field decode AD76 | `sub_10019C610` |
| Salt decode C5B | `sub_10019C630` |
| license hex decode | `sub_100106550` |
| S-box (256 x u32) | `dword_100B8D750` |

1. Search for the string `Invalid name or license` -> cross-reference -> `sub_100369C80`.
2. At the tail of that function there are two calls with the same arguments `(mgr, 17, 20300)`, producing a "router" `n231` and a "judge" `n219`.
3. Result code table: `45 -> 219` activated; `78 -> 237/524` license for an earlier version; `147 -> 113` trial; `231 -> 375` invalid.
4. `sub_100105E10`: empty-string check -> hex decode (length 19/24, position 4/9/14(/19) must be `-`) -> blacklist -> dispatch on type byte `b3`.
5. `0x9C` branch: `version = AD76(b0^b6)`, `salt = C5B((b1^b7)<<8 | (b2^b5))`, gate `version != 0 && salt in [1,1000]`, then compare `little_endian(hash(name)) == b4..b7`; `version < 17 -> 78`, otherwise `45`.
6. Generation: `b3 = 0x9C`, `b4..b7 = little_endian(hash(name, 1, 0, salt))`, then derive `b0..b2` so that version = 255 and the salt is valid.

Verification: the real machine code was extracted from IDA and executed under Unicorn emulation for `sub_10019C330/610/630`; the local implementation matches case by case, and a full "generate -> real decode -> real hash" round trip passes. See [`verify_emu.py`](verify_emu.py) for the reproducible harness.

## Build

```
cmake -B build && cmake --build build
# or
c++ -std=c++20 -O2 -o keygen main.cpp
```

## Usage

```
❯ ./keygen
Usage:
  keygen generate <name> [salt=1..1000] [version=17..255]
  keygen verify   <name> <license>
```

```
❯ ./keygen generate "smallsun"
Name    : smallsun
Salt    : 230  Version: 255
License : 936B-2E9C-262F-90E3
SelfTest: 45  [OK]
```

```
❯ ./keygen verify "smallsun" 936B-2E9C-262F-90E3
Name     : smallsun
License  : 936B-2E9C-262F-90E3
--- Decode ---
bytes    : 93 6B 2E 9C 26 2F 90 E3
type b3  : 0x9c (retail)
--- Fields ---
version  : 255  (AD76(b0^b6))
salt     : 230  (C5B((b1^b7)<<8|(b2^b5)))
hash     : 0xe3902f26  (calc_hash)
stored   : 26 2F 90 E3  (b4..b7)
checksum : match
--- Result ---
inner    : 45
[+] License activated. This license entitles you to Free Upgrades ...
```

## Verify (emulation)

`verify_emu.py` runs the *actual machine code* copied out of the binary (embedded as hex, so
it is reproducible without the target) and checks that keys from `./keygen` are accepted by it.

```
pip install unicorn
python3 verify_emu.py                 # default name set
python3 verify_emu.py "smallsun"      # custom names
```

```
[*] harness self-check  emu_hash(smallsun) = 0xE3902F26
PASS  'smallsun'               936B-2E9C-262F-90E3  ver=255 salt=230 hash=0xE3902F26
...
7/7 passed  [OK]
```

## Notes

- Names exactly equal to `999` / `AnyOne` are rejected outright; `generate` refuses them.
- Names starting with `CO` / `JU` are only rejected when paired with their leaked fingerprint, so generated keys for them are fine.
