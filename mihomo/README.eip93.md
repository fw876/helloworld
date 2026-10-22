# AN7581 EIP93 hybrid AES-GCM

Mihomo 1.19.32 package release 3 ports Xray's package-private Go AES-GCM
overlay. Eligible Go AES-GCM records use Linux AF_ALG with the exact
`gcm_base(ctr(aes-eip93),ghash-generic)` driver: hardware AES-CTR plus CPU
GHASH. Neither wire protocols nor the shared Go toolchain are changed.

## Selection and fallback

The package generates the overlay only for ARM64 builds. At runtime it:

- Requires root DT compatible `airoha,an7581` or `airoha,en7581` from sysfs
  or procfs, with a valid NUL-terminated property.
- Excludes AN7583/EN7583, CPUs with ARM AES instructions, FIPS mode and
  other/missing/malformed DT identities. There is no force-enable override.
- Handles standard 12-byte nonces, 16-byte tags, 4–32 KiB payloads and at
  most 256 bytes of associated data. Other requests use normal Go crypto.
- Verifies each new key against Go generic encryption/decryption and an
  invalid tag before offloading. Bounds operation sockets to 128,
  serializes operations per key and sets socket timeouts.
- Falls back to Go on missing modules, failed verification or operational
  errors. Authentication failures remain failures. Original Go overlap,
  length, nonce and authentication checks remain in place.

Set `MIHOMO_EIP93=off` in the process environment to disable acceleration.
The first verified activation logs:

```
Mihomo EIP93: AN7581 AES-GCM hybrid backend enabled (AF_ALG CTR + CPU GHASH)
```

Correlate traffic with `1fb70000.crypto` in `/proc/interrupts`; that log
message alone is not proof of throughput benefit. Socket timeouts cannot
recover a hung kernel DMA engine.

Firmware needs a working EIP93 driver/DT and GCM, GHASH and AF_ALG. On
QWRT, `kmod-crypto-hw-airoha-eip93` pulls in the crypto dependencies.
A missing driver safely leaves Mihomo on software. Hardware acceptance
below covers BSP Linux 5.4.302 on Nokia XG-040G-MD UBI, not AN7583 or every
kernel combination.

TLS/uTLS and protocols using Go AES-GCM can reach this path, but cipher
negotiation is unchanged: ChaCha20 connections are not AES-GCM acceleration
tests. Records outside the supported range also remain on software.

## Build and regression checks

The generator checks the Go source layout and fails on unknown layouts.
It was tested with Go 1.27.1. Files under `tools/eip93` use `.go.in`
templates so recursive Go package discovery does not compile them as an
application package importing Go internals. The generated overlay maps
these templates into the private standard-library build.

The patch replays with `patch --fuzz=0` on the source archive with SHA256:

```
0194b7039e6ff1143c7b80dd70d3a06976f60ff9f40802111d15a93da06c8a95
```

After preparing the patched source, use the same Go executable as the build:

```sh
python3 tools/eip93/overlay.py --go go --out "$PWD/.eip93-overlay"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test \
  -overlay="$PWD/.eip93-overlay/overlay.json" -c \
  -o gcm.test crypto/internal/fips140/aes/gcm
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test \
  -overlay="$PWD/.eip93-overlay/overlay.json" -c -o cipher.test crypto/cipher
```

Run `gcm.test -test.run TestEIP93 -test.v` and `cipher.test -test.short` on
AN7581. Both passed, including AES-128/192/256, payload boundaries, in-place
buffers, invalid tags, concurrency, closed-socket fallback, DT exclusions
and nonstandard nonce/tag fallback. Host AMD64 cipher tests also passed
with the overlay present and the hardware path excluded.

## Pristine/patched cross-validation

The ordinary ARM64 and AMD64 peers were built from the pristine archive,
not patched source with acceleration switched off. Ordinary and patched
ARM64 builds both use Go 1.27.1, musl/CGO, `with_gvisor`, ARM64 v8.0 and
UPX compression. The accelerated artifact came from the OpenWrt package.
The independent off-switch test uses that same accelerated binary with
`MIHOMO_EIP93=off`.

The local `eip93-interop.py` validation script, retained with the evidence
listed below, alternates ordinary and accelerated router builds,
then exchanges client/server roles against the ordinary host build. Each
case uploads and downloads 32 MiB through SOCKS and Shadowsocks, verifying
SHA256 at both ends. It asserts activation and IRQ growth for accelerated
runs, and no activation/IRQ growth for software controls. It restores the
CPU governor and removes its own processes/firewall rules. Do not run it
with other EIP93 workloads, which would pollute the counter comparison.
It uses TCP ports 24443–24445 and requires sshpass/SSHPASS, nftables and
already trusted SSH host keys. Keep generated configurations private.

Example after uploading both router binaries:

```sh
python3 /path/to/eip93-interop.py \
  --router root@192.168.0.168 --host-ip 192.168.0.104 \
  --host-binary /path/to/mihomo-plain-amd64 \
  --plain-binary /tmp/mihomo-eip93/mihomo-plain-arm64 \
  --accelerated-binary /tmp/mihomo-eip93/mihomo-accelerated-arm64 \
  --out /path/to/private-test-results
```

Nokia XG-040G-MD, AN7581 at 1.2 GHz, Gigabit LAN, 2026-10-22. Mean Mbps
of two alternating samples; send/receive are from the router's perspective:

| Router role | Shadowsocks AES-256-GCM build | Send | Receive |
| --- | --- | ---: | ---: |
| Client | Pristine | 34.2 | 32.1 |
| Client | EIP93 | 146.0 | 100.0 |
| Server | Pristine | 35.4 | 34.5 |
| Server | EIP93 | 149.1 | 109.5 |

All eight runs and both off-switch controls passed. Accelerated runs added
4104–4105 interrupts each; pristine and off-switch controls added zero.
Every transfer agreed on SHA256:

```
e09320c5b00b34bb704802136c599a95b3996332ba84d7c7f21112b6231b6bd0
```

These are single-stream application payload measurements, not raw AES
throughput or a complete regression of every Mihomo protocol. Local raw
evidence and artifact hashes are under
`/home/lean/Desktop/airoha-5.4-evidence/mihomo-eip93-20261022/`.

Shadowsocks 2022 (`--cipher 2022-blake3-aes-256-gcm --repeats 1`) also
passed the pristine/accelerated cross in both roles plus both off-switch
controls. Single-sample send/receive Mbps:

| Router role | Pristine | EIP93 |
| --- | ---: | ---: |
| Client | 35.9 / 36.2 | 159.0 / 113.0 |
| Server | 35.8 / 35.8 | 154.5 / 120.9 |

Those accelerated runs added 2057 and 2058 interrupts. All software
controls added zero, and all six transfers matched the same SHA256.
