# AN7581 EIP93 hybrid AES-GCM

Xray 26.10.21 adds an automatic AN7581-only AES-GCM path through Linux AF_ALG.
EIP93 performs AES-CTR; GHASH stays on the CPU. This is not native hardware GCM.

The ARM64 package build generates a private Go source overlay. It never changes
the shared toolchain. The overlay is checked against Go 1.27's implementation;
unknown source layouts fail the build so that they can be reviewed explicitly.
Go TLS/uTLS and other users of Go AES-GCM can use it. Native Cronet TLS does not.
TLS framing, nonce management, overlap checks and authentication checks remain
in their original implementations.

## Automatic selection and fallback

- Read the NUL-delimited root DT `compatible` property from sysfs or procfs.
- Enable only `airoha,an7581` / `airoha,en7581`, with no ARM AES instructions.
- Explicitly exclude AN7583/EN7583, other platforms, missing/malformed DT and FIPS.
- Use only standard 12-byte nonces, 16-byte tags and 4–32 KiB payloads.
- Bind `gcm_base(ctr(aes-eip93),ghash-generic)` on older kernels, retrying
  `gcm_base(ctr(aes-eip93),ghash-lib)` on kernels such as 7.3 when the old
  name is unavailable. Both names require the exact EIP93 CTR driver.
- Verify each newly opened key against Go encryption/decryption and bad-tag
  rejection before using it. Bound sockets, serialize each key's operations,
  set socket timeouts and clear private buffers. The kernel must also be healthy;
  socket timeouts do not recover a hung DMA engine.
- Missing modules, failed verification or syscall errors use the original Go
  implementation. Authentication failures remain failures.
- `XRAY_EIP93=off` disables the optimization; there is no force-enable override.

The first successful activation prints:
`Xray EIP93: AN7581 AES-GCM hybrid backend enabled (AF_ALG CTR + CPU GHASH)`.
This message alone is not performance evidence; use engine interrupt counters.

Firmware needs `kmod-crypto-hw-airoha-eip93`, `kmod-crypto-gcm`, `kmod-crypto-user` and
GHASH/DES dependencies. The QWRT EIP93 package selects these dependencies.
BSP 5.4 needs the supplied driver and DT node. Linux 6.18 uses its native driver
with matching DMA cache-line and immutable-SA fixes. Linux 7.3 carries the
same protections plus the CTR next-IV carry fix, and additionally
needs the supplied AF_ALG exception for the exact EIP93 hybrid GCM driver;
leave `crypto.af_alg_restrict` at its default value. Native hardware authenc
is withheld because its bad-tag tests fail; hybrid GCM authenticates through
the kernel GCM implementation and passes its own bad-tag tests. AN7583 remains on the normal
Xray path until separate hardware measurements justify an alternative.

## Validation

The entire 100–190 patch stack replays on the official 26.10.21 archive with
`patch --fuzz=0`. The version upgrade refreshed dependency contexts and fixed
patch 100's TLS protobuf descriptor length; `infra/conf` tests catch that issue.
Existing protocol packages compile and their available tests pass. The ARM64
OpenWrt package also builds with `with_naive_outbound with_musl` and Cronet LLD.
This is not a claim of rerunning every historical cross-core protocol matrix.

On Nokia XG-040G-MD UBI / AN7581 / Linux 5.4.302:

- AES-128/192/256 comparisons against the independent Go generic implementation.
- Payload boundaries, in-place operations, corrupted tags, concurrent requests,
  closed-socket fallback, nonstandard nonce/tag exclusion and the off switch.
- Go `crypto/cipher` short regression suite on the device.
- Ordinary client → optimized server and optimized client → ordinary server,
  plus ordinary controls, using VLESS/TLS 1.2 AES-256-GCM. Each connection sends
  and receives deterministic data and checks SHA-256. Hardware interrupts grow
  only in optimized runs.

Local raw evidence and reproducible test sources:
`/home/lean/Desktop/airoha-5.4-evidence/eip93-20261022/`.

## Final Xray throughput

VLESS/TLS 1.2, server restricted to AES-256-GCM, same patched source and
Naive/Cronet build features. AN7581 at 1.2 GHz, Gigabit LAN. Each of two
alternating runs per row sends and receives 32 MiB and verifies SHA-256.
The optimized binary is the packaged UPX artifact; startup completes before
timing. Both ordinary-client/optimized-server and optimized-client/ordinary-
server directions passed. Values are mean Mbps; connection/relay overhead is
included. Receive results varied roughly 95–112 Mbps across optimized runs.
These final measurements use the driver extracted from the final IPK, including
the immutable-SA and native-authenc fixes; see `xray-e2e-packaged-final.log`.

| AN7581 role | Build | Router sends | Router receives |
| --- | --- | ---: | ---: |
| server | normal | 35.0 | 32.1 |
| server | eip93 | 136.6 | 98.2 |
| client | normal | 34.4 | 32.5 |
| client | eip93 | 133.3 | 104.5 |

All eight runs agree on SHA-256:
`e09320c5b00b34bb704802136c599a95b3996332ba84d7c7f21112b6231b6bd0`.
Ordinary runs add no EIP93 interrupts; each optimized run adds 8198.

This supports enabling the AN7581 path for bulk Go AES-GCM traffic, with
roughly 3–4x throughput versus ordinary Go. It does not imply gigabit GCM,
the same gain over optimized OpenSSL, or any measured benefit on AN7583.

The packaged binary with `XRAY_EIP93=off` also passed bidirectional hash
checks at 33.5/34.9 Mbps, with no EIP93 interrupt increase. The host AMD64
Go cipher regression passes with the overlay present and acceleration disabled.

The native-authenc quarantine preserves the kernel `authenc` composition over
EIP93 CBC/HMAC primitives. That composed implementation passes 12- and 13-byte
AAD encryption/decryption and corrupted-tag tests; `/proc/crypto` identifies
its module as `authenc`, rather than `crypto_hw_eip93`.

The final Nokia UBI firmware builds and includes Xray 26.10.21, EIP93, libdes,
GCM, GHASH and AF_ALG modules. Its embedded FIT DTB has the EIP93 node at
0x1fb70000 / GIC SPI 44. All 16 generated AN7581 BSP DTBs contain that node,
including standalone Nokia, Fiberhome and W1700K DTS layouts.

The final image passes `sysupgrade -T` on the Nokia test board
(`Signature check OK`). This validates the image without flashing it.
The board governor is restored to `schedutil` and test proxy processes stop
after each run. The final driver remains loaded temporarily for inspection.

## Linux 7.3 regression validation (2026-10-29)

On H3C HM2004-DU, five repeated hardware test runs passed AES-128/192/256-GCM,
boundary lengths, in-place operations, concurrent use, bad-tag rejection and
closed-socket fallback. CBC encrypt/decrypt/encrypt and CTR exact-rollover IV
tests failed with the original 7.3 driver and passed after the driver fixes.
The packaged Xray completed a 4 MiB AES-256-GCM Shadowsocks transfer with
matching SHA-256 and EIP93 activation at both ends. The disabled backend
completed the same transfer without increasing EIP93 interrupts.
`crypto.af_alg_restrict` remained at 1. These are correctness checks, not
throughput measurements. The legacy 5.4 name is retained; 5.4 hardware was
not rerun in this validation.
