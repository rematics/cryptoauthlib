# Patch Security Justification — Trust PKCS#11 / AWS Greengrass Interoperability

This document explains and defends the changes that Rematics made to this
library. Changes 1 to 3 are in commit `9c9b44991` ("Fix Trust PKCS11 device
certificate ID handling"). The changes make the Microchip cryptoauthlib
PKCS#11 provider work correctly with AWS Greengrass v2 on Trust&GO / TNGTLS /
TrustFlex devices. Change 4 makes command execution reliable when other
devices share the I²C bus at low speed.

Greengrass v2 consumes PKCS#11 through its
`aws.greengrass.crypto.Pkcs11Provider` Java plugin, which registers a
`SunPKCS11` `java.security.Provider` pointing at `libcryptoauth.so` and
loads the token as a Java `KeyStore`. "Greengrass" and "SunPKCS11" in this
document therefore refer to the same runtime consumer.

Each change is analyzed below for correctness and security impact.

---

## 1. `app/pkcs11/trust_pkcs11_config.c` — Guard hardcoded key objects

### Change
The block in `pkcs11_trust_load_objects()` that allocates and configures the
slot-0 device private key and device public key objects is now wrapped in
`#if PKCS11_USE_STATIC_CONFIG`.

### Why it was needed
Without the guard, in dynamic-config builds
(`PKCS11_USE_STATIC_CONFIG=OFF`, e.g. the AWS Greengrass build) the slot-0
device private/public key objects were being loaded **twice**:

1. Once hardcoded here, with the static Trust labels.
2. Again from the filestore configuration that `pkcs11_config_load_objects`
   invokes downstream.

Duplicate objects with the same `CKA_LABEL` / `CKA_ID` cause
`C_FindObjects` to enumerate both, and Greengrass's KeyStore mapping may
bind to the wrong instance — leading to inconsistent KeyStore mappings or
spurious "object already exists" conditions during KeyStore load.

### Security analysis
- **No new attack surface.** The same key material remains exposed via the
  dynamic path; only the redundant static instantiation is suppressed.
- **Reduces ambiguity, which is a security property.** A PKCS#11 token
  presenting two distinct objects for the same private key is a correctness
  smell that can confuse relying-party logic. Eliminating the duplicate is
  strictly safer than leaving it.
- **Build-flag consistency.** The static key-object block was already
  intended for static-config embedded builds — the rest of the file already
  uses `#if PKCS11_USE_STATIC_CONFIG` to gate `pkcs11_config_cert`,
  `pkcs11_config_key`, and `pkcs11_config_load_objects`. This change makes
  the load path consistent with the rest of the file's existing convention.
- **No behavior change in static-config builds** — the guard evaluates true
  and the block is compiled exactly as before.

### Risk
Low. The only behavioral change occurs in dynamic-config builds, where it
removes an unintended duplicate. Static-config builds are byte-for-byte
identical to before.

---

## 2. `lib/pkcs11/pkcs11_cert.c` — Subject Key Identifier fallback

### Change
In `pkcs11_cert_get_subject_key_id()`, when the primary SKI derivation fails,
fall back to:

1. `atcacert_get_subj_public_key(cert_cfg, NULL, 0, &subj_pubkey)` followed by
   `atcacert_get_key_id(&subj_pubkey, subj_key_id)` — i.e.
   `SHA1(0x04 || subject_public_key)`.
2. If still unsuccessful and `ATCACERT_COMPCERT_EN` is enabled,
   `atcacert_read_subj_key_id_ext(...)` as a last-resort device read.

Only if all fallbacks fail does the function return `CKR_DEVICE_ERROR` (the
previous unconditional behavior).

### Why it was needed
Some Trust&GO / TNGTLS certificate definitions do not carry a Subject Key
Identifier X.509 extension, so `atcacert_get_subj_key_id()` returns a
non-success status. The previous code immediately returned `CKR_DEVICE_ERROR`,
leaving the certificate object with no usable `CKA_ID`.

PKCS#11 consumers like AWS Greengrass v2 pair a certificate to its private
key by matching `CKA_ID` when loading the token as a Java `KeyStore`.
Without a matching `CKA_ID`, Greengrass cannot map the KeyStore entry and
the Trust&GO device is unusable from Greengrass.

### Why this derivation is correct and safe
The private key object's `CKA_ID` is derived in
`pkcs11_key_calc_key_id()` (`lib/pkcs11/pkcs11_key.c:604`) as:

```
SHA1(0x04 || public_key)
```

where `0x04` is the SEC1 uncompressed-point type byte and `public_key` is the
64-byte X||Y public key read from the device slot.

`atcacert_get_key_id()` (`lib/atcacert/atcacert_def.c:2440`) computes the
**byte-for-byte identical** value:

```c
msg[0] = 0x04;
memcpy(&msg[1], public_key->buf, public_key->len);
atcac_sw_sha1(msg, 1 + public_key->len, key_id);
```

Therefore the certificate's fallback `CKA_ID` provably matches the private
key's `CKA_ID` whenever both derive from the same key pair. This is also the
derivation method mandated by RFC 5280 §4.2.1.2 method (1) for
SubjectKeyIdentifier, so it is the standards-compliant choice.

### Security analysis
- **No attacker-controlled input.** The fallback only executes when
  `read_cache == CKR_OK`, meaning the certificate definition was loaded from
  the device's own provisioned compressed-cert chain via
  `pkcs11_cert_load_cache()` — not from any caller-supplied buffer. An
  attacker would need to have already compromised the Trust&GO provisioning
  flow at the Microchip factory to influence this input.
- **Mis-derivation cannot cause key mis-binding.** If the fallback produced
  a wrong `CKA_ID`, the symptom would be a *pairing failure* (the cert would
  not be linked to the private key in the KeyStore), not a binding to a
  different key. The failure mode is availability, not confidentiality or
  authenticity.
- **Fallback ordering is least-surprising.** The in-memory
  `atcacert_get_subj_key_id` is tried first (fast, no device I/O); the
  SHA-1-of-public-key derivation second (matches the key object's
  derivation exactly); the device-side
  `atcacert_read_subj_key_id_ext` last (involves a bus transaction). Each
  step is strictly more expensive than the previous.
- **No regression.** The previous behavior on total failure
  (`CKR_DEVICE_ERROR`) is preserved as the final return path.
- **Consistent with existing usage.** The same
  `atcacert_get_subj_public_key(cert_cfg, NULL, 0, &subj_pubkey)` call
  pattern is already used elsewhere in this file (see the `CKA_PUBLIC_KEY`
  attribute handler around `pkcs11_cert.c:850`), so the fallback reuses an
  established, audited code path.

### Risk
Low. The fallback is gated on trusted inputs, produces the canonical SKI
value, and degrades to the original error path if all derivations fail.

---

## 3. `lib/pkcs11/pkcs11_token.c` — Advertise real session limit

### Change
`pkcs11_token_get_info()` previously reported:

```c
pInfo->ulMaxSessionCount    = 1;
pInfo->ulMaxRwSessionCount  = 1;
pInfo->ulSessionCount       = (slot_ctx->session != 0u) ? 1u : 0u;
pInfo->ulRwSessionCount     = (slot_ctx->session != 0u) ? 1u : 0u;
```

It now reports:

```c
pInfo->ulMaxSessionCount    = PKCS11_MAX_SESSIONS_ALLOWED;
pInfo->ulMaxRwSessionCount  = PKCS11_MAX_SESSIONS_ALLOWED;
pInfo->ulSessionCount       = CK_UNAVAILABLE_INFORMATION;
pInfo->ulRwSessionCount     = CK_UNAVAILABLE_INFORMATION;
```

### Why it was needed
The library has always supported up to `PKCS11_MAX_SESSIONS_ALLOWED` (default
10) concurrent sessions via a static session pool
(`lib/pkcs11/pkcs11_session.c:51`). The reported `ulMaxSessionCount = 1` was
therefore an understatement of the library's actual capability.

AWS Greengrass v2 opens **nested** `C_OpenSession` calls while mapping a
PKCS#11 KeyStore to its internal representation — a login session, plus
operation sessions for `C_FindObjects`, `C_GetAttributeValue`, etc. With
the reported limit of 1, Greengrass either refuses to load the token or
deadlocks waiting for the existing session to close. Advertising the real
limit lets Greengrass allocate the sessions it needs.

### Security analysis
- **No new session capability is created.** The library already allowed up
  to `PKCS11_MAX_SESSIONS_ALLOWED` sessions; the change only corrects what
  `C_GetTokenInfo` *reports* to align with reality.
- **No weakening of session isolation.** Each session still gets its own
  `pkcs11_session_ctx` from the static pool; session contexts are not shared
  or merged. The existing session lifecycle enforcement in
  `pkcs11_session.c` is unchanged.
- **`CK_UNAVAILABLE_INFORMATION` is spec-compliant** (PKCS#11 v3.0,
  `CK_TOKEN_INFO`). The previous `(slot_ctx->session != 0u) ? 1u : 0u`
  heuristic was already inaccurate — it was a per-slot single-bit flag, not
  a real count of live `C_OpenSession` handles against that slot. Reporting
  "unavailable" is more honest than reporting a known-wrong number.
- **No authentication bypass.** `CKF_LOGIN_REQUIRED` is commented out in
  both the old and new code, so session count was never load-bearing for
  access control on this token. The change does not alter the token's
  authentication posture.
- **DoS consideration.** A malicious caller could now open up to
  `PKCS11_MAX_SESSIONS_ALLOWED` sessions instead of being rejected at 1.
  This is already the case regardless of the reported value (the library
  enforces the real pool limit, not the reported limit), and the pool is a
  fixed-size static array, so worst-case behavior is bounded and identical
  to before.

### Risk
Low. The change aligns the reported token info with the library's actual,
pre-existing session support and is required for AWS Greengrass interoperability.
No new sessions are possible beyond what the library already permitted.

---

## 4. `lib/calib/calib_execution.c` — Send Idle before Wake

### Change
`calib_execute_command()` now sends the Idle sequence (word address `0x02`)
immediately before it sends the Wake token. It does this only when the
device state is not `ATCA_DEVICE_STATE_ACTIVE`. It does not do this for CA2
devices. The existing Idle at the end of the function uses the same rule.

```c
if ((uint8_t)ATCA_DEVICE_STATE_ACTIVE != device->device_state)
{
    if (!atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype))
    {
        (void)calib_idle(device);
    }

    if (ATCA_SUCCESS == (status = calib_wakeup(device)))
    ...
```

The library sets the device state to `ATCA_DEVICE_STATE_IDLE` at the end of
each command. Thus, the library sends the new Idle before each command.

### Why it was needed
On the Rematics edge devices, the ATECC608B-TNGTLS (address `0x35`) shares
I²C bus 1 with the BMU (`0x4b`) and two INA3221 power monitors (`0x40`,
`0x41`). The bus speed is 100 kHz. `hostagent-service` reads a BMU GPIO
every 500 ms.

The ATECC608B-TNGTLS data sheet (DS40002250A) gives these facts:

- Section 7.1.1: "When there are multiple devices on the bus and the I²C
  interface is run at speeds of less than ~300 kHz, the transmission of
  certain data patterns will cause the ATECC608B-TNGTLS devices on the bus
  to wake up." The data sheet recommends: "after communicating with
  another device at slow frequencies, a sleep or idle sequence be issued to
  place the ATECC608B-TNGTLS back into a known state."
- Section 7.1.1: "In the I²C mode, the device will ignore a wake sequence
  that is sent when the device is already awake."
- Section 2.1 and Table 8-2: the watchdog time-out is 0.7 s to 1.7 s
  (typical 1.3 s). The time starts at wake.
- Section 7.4 and Table 4-3: only the Idle or Sleep mode resets the
  watchdog. If too little watchdog time remains for a command, the device
  returns status `0xEE` ("Watchdog About to Expire").

The failure sequence is as follows:

1. Traffic to another device wakes the ATECC608B. Its watchdog starts.
2. The library sends its Wake token. The device is awake, so it ignores the
   token. The watchdog continues.
3. The library reads the old wake reply `04 11 33 43`. The library thinks
   that the device is fresh.
4. The library sends a command. Too little watchdog time remains. The
   device returns `04 EE 31 41`.
5. `isATCAError()` has no case for `0xEE`. It returns `ATCA_GEN_FAIL`.
   `calib_execute_command()` does not try the command again.

In PKCS#11, `pkcs11_key_get_key_id()` reads the public key with GenKey. If
this read fails, the function returns an empty `CKA_ID`. SunPKCS11 then
cannot pair the private key with the certificate (see change 2). Greengrass
then reports: "Private key or certificate with label device does not
exist". A deployment can fail with `FAILED_NO_STATE_CHANGE` for this reason.

With the new Idle, the device goes into Idle mode before the Wake token.
Thus, the Wake token is not ignored, and each command starts with a full
watchdog window.

### Evidence
These results are from 2026-11-19:

- **rematics-260019, 08:10:40 UTC.** A Greengrass deployment failed with
  the error above. The I²C trace shows the wake reply `04 11 33 43`, then
  GenKey for slot 0, then the reply `04 EE 31 41`.
- **Accidental wake.** A read probe at address `0x35`, every 1.7 s, with no
  software that uses the device: the device acknowledged 27 of 30 probes on
  rematics-260019 and 27 of 30 probes on rematics-260018. The device ACKs
  its address only when it is awake.
- **Reproduction on rematics-260018.** 60 runs of `p11tool --list-all`, each
  after a 3 s pause: 38 runs failed. Each failed run had one `0xEE` reply
  on its first command. No successful run had an `0xEE` reply.
- **Idle before the run (no library change).** `i2ctransfer -y 1 w1@0x35
  0x02` before `p11tool`: 0 of 40 runs failed. Without the Idle, 19 of 40
  runs failed at the same time.
- **Patched library on rematics-260018.** Each run sent Idle and a Wake
  pulse, waited for a time D, then started `p11tool`:

  | D | Original library | Patched library |
  |---|------------------|-----------------|
  | 0.90 s to 1.15 s | 0 of 20 runs failed | 0 of 20 runs failed |
  | 1.20 s to 1.30 s | 15 of 15 runs failed, each with `0xEE` | 0 of 15 runs failed |

### Build
The production `libcryptoauth.so` (build ID
`b6d205ab6be61764c14e73c9aea5f6fed9286c2e`) was reproduced bit for bit from
commit `5f16349` with these settings:

- Image `ubuntu:22.04` with `gcc-11`, `cpp-11`, `gcc-11-base`,
  `libgcc-11-dev` and `libasan6` at version `11.4.0-1ubuntu1~22.04` (arm64,
  from Launchpad).
- Source directory `/work/cryptoauthlib`, build directory
  `/work/cryptoauthlib/build-greengrass-systemconf`.
- CMake options: `-DATCA_HAL_I2C=ON -DATCA_PKCS11=ON
  -DATCA_TNGTLS_SUPPORT=ON -DDEFAULT_CONF_PATH=/etc/cryptoauthlib
  -DDEFAULT_STORE_PATH=/var/lib/cryptoauthlib`. The build type is the
  default (`RelWithDebInfo`).

The same build with this change is different only in
`calib_execute_command()`. It has one more call to `atcab_is_ca2_device()`
and one more call to `calib_idle()`.

### Security analysis
- **No new command.** The Idle sequence is a standard I/O sequence. The
  library already sends it after each command.
- **Volatile state is kept.** Idle keeps TempKey, the Message Digest Buffer
  and the Alternate Key (Table 7-2). Thus, command sequences such as
  Random, Nonce and Sign in `calib_sign()` continue to work. Sleep clears
  this state. For this reason, the change uses Idle and not Sleep.
- **Asleep device.** If the device is asleep, it does not acknowledge the
  Idle. The library ignores this result. The Wake token then operates as
  before.
- **No change to keys or data.** The change does not change key access,
  slot configuration or the data that the device returns.
- **Multiple processes.** The change does not fix the known problem when
  more than one process uses the device at the same time. The change adds
  one transfer to each command. Thus, the time window for this known
  problem is slightly larger.

### Cost
One more I²C write for each command. At 100 kHz, this write takes
approximately 0.2 ms to 0.3 ms.

### Risk
Low. The change uses an existing, documented I/O sequence that the data
sheet recommends for this bus configuration. It does not change the result
of a command when the device is in a known state. Tests with `p11tool` show
no failures. Tests with the Greengrass Nucleus and the patched library are
not done yet.

---

## Summary

| # | File | Change | Security risk | Benefit |
|---|------|--------|---------------|---------|
| 1 | `app/pkcs11/trust_pkcs11_config.c` | Gate static key-object load on `PKCS11_USE_STATIC_CONFIG` | None | Eliminates duplicate objects in dynamic-config builds |
| 2 | `lib/pkcs11/pkcs11_cert.c` | Fallback SKI derivation via `SHA1(0x04 \|\| subj_pubkey)` | None (trusted input, canonical derivation) | Cert/key `CKA_ID` pairing works on Trust&GO/TNGTLS without SKI extension |
| 3 | `lib/pkcs11/pkcs11_token.c` | Report `PKCS11_MAX_SESSIONS_ALLOWED` instead of `1` | None (no new capability) | Greengrass nested-session KeyStore mapping succeeds |
| 4 | `lib/calib/calib_execution.c` | Send Idle before Wake in `calib_execute_command()` | None (existing I/O sequence, volatile state kept) | No `0xEE` failure when other bus traffic woke the device |

Changes 1 to 3 are minimal, consistent with existing code conventions in
the library, and produce no regression on the original error/failure paths.
They collectively enable Trust&GO / TNGTLS / TrustFlex devices to be
consumed by AWS Greengrass v2 — a standard, supported PKCS#11 consumer —
without compromising the library's security model.

Change 4 adds one Idle sequence before each Wake token. It makes command
execution reliable when other devices share the I²C bus at low speed. It
does not change the trust model below.

### Trust model unchanged
- Private keys remain non-extractable; the changes do not alter any
  `C_GenerateKeyPair`, `C_Sign`, or slot-access code path.
- The Trust&GO device's secure boot / secure storage model is not touched.
- No new trust is placed in caller-supplied data; all fallback inputs come
  from the device's own provisioned certificate chain.
