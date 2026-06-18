# Patch Security Justification — Trust PKCS#11 / AWS Greengrass Interoperability

This document explains and defends the three changes introduced in commit
`9c9b44991` ("Fix Trust PKCS11 device certificate ID handling"). The changes
make the Microchip cryptoauthlib PKCS#11 provider work correctly with
AWS Greengrass v2 on Trust&GO / TNGTLS / TrustFlex devices.

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

## Summary

| # | File | Change | Security risk | Benefit |
|---|------|--------|---------------|---------|
| 1 | `app/pkcs11/trust_pkcs11_config.c` | Gate static key-object load on `PKCS11_USE_STATIC_CONFIG` | None | Eliminates duplicate objects in dynamic-config builds |
| 2 | `lib/pkcs11/pkcs11_cert.c` | Fallback SKI derivation via `SHA1(0x04 \|\| subj_pubkey)` | None (trusted input, canonical derivation) | Cert/key `CKA_ID` pairing works on Trust&GO/TNGTLS without SKI extension |
| 3 | `lib/pkcs11/pkcs11_token.c` | Report `PKCS11_MAX_SESSIONS_ALLOWED` instead of `1` | None (no new capability) | Greengrass nested-session KeyStore mapping succeeds |

All three changes are minimal, consistent with existing code conventions in
the library, and produce no regression on the original error/failure paths.
They collectively enable Trust&GO / TNGTLS / TrustFlex devices to be
consumed by AWS Greengrass v2 — a standard, supported PKCS#11 consumer —
without compromising the library's security model.

### Trust model unchanged
- Private keys remain non-extractable; the changes do not alter any
  `C_GenerateKeyPair`, `C_Sign`, or slot-access code path.
- The Trust&GO device's secure boot / secure storage model is not touched.
- No new trust is placed in caller-supplied data; all fallback inputs come
  from the device's own provisioned certificate chain.
