# dSD-JWT chain — acronym & term glossary

A decoder ring for AP2's delegated mandate format and the verifier's chain walk.
Every acronym used in the verification flow, expanded. Protocol-only (no
deployment internals).

---

## The chain walk, fully expanded

```
1. Root SD-JWT (Selective-Disclosure JSON Web Token),
   signed by the ISSUER's root key
     → trust that key via:
         kid  (key id)  → look it up in a local trusted-key list, OR
         x5c  (X.509 certificate chain) → verify it chains to a trusted root CA
     → root payload carries cnf.jwk (confirmation key)  = the AGENT's public key
       i.e. "the next signer must be whoever holds this key"

2. KB-SD-JWT (Key-Binding SD-JWT) hop, signed by the AGENT
   (the key the previous segment's cnf named) — verified with that key
     → if INTERMEDIATE: its payload carries the next cnf.jwk   (MUST have cnf)
     → if TERMINAL:    NO cnf; carries the payment + aud + nonce,
                       bound to the prior segment via sd_hash   (end of line)

The whole thing assembled = a dSD-JWT (delegated SD-JWT) chain:
   root[:-1] ~~ intermediate[:-1] ~~ terminal
```

One **root trust decision** (`kid` or `x5c`) followed by a chain of **`cnf`
hand-offs** ending at a **terminal** hop that does the actual spend.

---

## Actors

| Term | Meaning |
|---|---|
| **Issuer** | Holds the **private** signing key; mints the root mandate ("this user authorized $X"). Sits at the top of the chain. |
| **Holder / Agent** | The party named by the previous segment's `cnf`; signs the next hop. The AI doing the buying. |
| **Verifier** | Checks the chain. Holds only **public** keys. Never signs. |
| **Merchant** | The relying party; issues the `nonce`, sets the `aud`, calls verify. |

## Container formats

| Acronym | Expansion | What it is |
|---|---|---|
| **JOSE** | JSON Object Signing and Encryption | Umbrella family of JSON crypto standards (JWS/JWE/JWK/JWA/JWT). The `jose` npm lib. |
| **JWT** | JSON Web Token | A signed/encoded set of claims. `header.payload.signature`, base64url. (RFC 7519) |
| **JWS** | JSON Web Signature | The signing structure under a JWT. (RFC 7515) |
| **JWK** | JSON Web Key | A public (or private) key as a JSON object: `{kty, crv, x, y, kid}`. (RFC 7517) |
| **JWKS** | JSON Web Key **Set** | A list of JWKs, usually served at an HTTPS endpoint. (Not used by AP2's trust model.) |
| **SD-JWT** | Selective-Disclosure JWT | A JWT where some claims are hidden behind salted hashes and revealed ("disclosed") selectively. IETF OAuth SD-JWT spec. |
| **KB-SD-JWT** | Key-Binding SD-JWT | An SD-JWT with a trailing JWT proving the holder possesses a key (`cnf`) and binding to a context (`aud`, `nonce`). Each delegation hop. |
| **dSD-JWT** | delegated SD-JWT | AP2's construction: a root SD-JWT plus KB-SD-JWT hops chained together to delegate authority down a path. |

## Claims (inside the payload)

| Claim | Name | Role in AP2 |
|---|---|---|
| **`cnf`** | confirmation (RFC 7800) | `{jwk: <pubkey>}` — names the key allowed to sign the **next** hop. The delegation link. Intermediate MUST have it; terminal MUST NOT. |
| **`iss`** | issuer | A name string identifying who issued the token. **Not used by AP2's SD-JWT mandate** (trust is by key, not name). Used in AP2 *receipts*. |
| **`sub`** | subject | Who the token is about. |
| **`aud`** | audience | Who the token is *for*. The verifier forces this to the merchant's identity so a presentation can't be replayed at another merchant. |
| **`nonce`** | number used once | A one-time challenge the merchant issues; binds the presentation to this request (anti-replay). |
| **`iat`** | issued-at | Unix timestamp the token was created. |
| **`exp`** | expiration | Unix timestamp after which the token is invalid. |
| **`sd_hash`** | selective-disclosure hash | Binds a hop to the exact previous segment by hashing it. One of two binding modes. |
| **`issuer_jwt_hash`** | issuer-JWT hash | Alternate binding mode: hashes just the previous issuer JWT. Exactly one of `sd_hash`/`issuer_jwt_hash` must be present. |
| **`_sd`** | selective disclosure | Array of digests of the hidden claims inside an SD-JWT. |
| **`_sd_alg`** | SD algorithm | The hash algorithm used for the `_sd` digests (e.g. sha-256). |
| **disclosure** | — | The salted plaintext (`[salt, name, value]`) that, when hashed, matches an `_sd` digest. Revealing it "discloses" the claim. |

## Header parameters

| Param | Name | Role |
|---|---|---|
| **`alg`** | algorithm | Signature algorithm. AP2/verifier pins **ES256**; `none`, `HS256`, `ES384` are rejected. |
| **`typ`** | type | Token type marker (distinguishes root / intermediate / terminal SD-JWT forms). |
| **`kid`** | key id | Identifier used to look the verifying key up in a **local trusted-key list** ("key ring" trust). |
| **`x5c`** | X.509 certificate chain | A list (leaf → intermediate) of base64url-DER certs carried in the header; trust = the chain anchors to a configured root CA. |

## Cryptography

| Acronym | Expansion | Note |
|---|---|---|
| **ES256** | ECDSA using P-256 and SHA-256 | The only signature alg AP2 mandates accept (per JWA, RFC 7518). |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm | The signing scheme behind ES256. |
| **EC** | Elliptic Curve | The JWK `kty` (key type) for these keys. |
| **P-256** | NIST P-256 curve | a.k.a. `secp256r1` / `prime256v1`. The required curve. |
| **JWK thumbprint** | RFC 7638 | A hash of a public JWK's canonical form. The verifier keys a budget on `thumbprint(root key) × terms` — a stable issuer identity without needing `iss`. |
| **HS256** | HMAC-SHA-256 | Symmetric alg; **rejected** (an attacker could forge with the public key as the HMAC secret — the classic alg-confusion attack). |
| **`none`** | no signature | The unsigned JWS alg; **rejected** (downgrade attack). |

## Certificates (the `x5c` path)

| Acronym | Expansion | Note |
|---|---|---|
| **X.509** | — | The standard certificate format (RFC 5280). |
| **CA** | Certificate Authority | An entity allowed to sign (vouch for) other certs. |
| **PEM** | Privacy-Enhanced Mail | Text encoding: base64 between `-----BEGIN/END CERTIFICATE-----`. How trusted roots are configured. |
| **DER** | Distinguished Encoding Rules | Binary cert encoding. The `x5c` header carries base64url-DER. |
| **basicConstraints CA:TRUE** | — | Cert extension marking a cert as a CA. The verifier requires it on every issuer in the chain. |
| **KeyUsage / pathLenConstraint** | — | Further X.509 constraints. (Documented limitation: Node's `X509Certificate` doesn't expose basic KeyUsage, so it isn't fully enforced — see `keys.ts`.) |

## Chain-position terms

| Term | Meaning |
|---|---|
| **root** | The first segment — an SD-JWT signed by the issuer, trust-anchored via `kid`/`x5c`. |
| **hop** | One KB-SD-JWT delegation step. |
| **intermediate** | A non-final hop; MUST carry a `cnf` naming the next signer. |
| **terminal** | The final hop; carries the payment, `aud`, `nonce`; MUST NOT carry `cnf`; binds via `sd_hash`/`issuer_jwt_hash`. |
| **binding** | Cryptographically tying a hop to the exact preceding segment (so hops can't be spliced across chains). |

## AP2 objects

| Term | Meaning |
|---|---|
| **OpenPaymentMandate** | The open-ended root mandate (constraints + `cnf`), not yet a specific purchase. |
| **PaymentMandate** | The terminal mandate naming a concrete payment (payee, amount, instrument). |
| **IntentMandate** | A mandate expressing user intent / budget terms. |
| **PaymentReceipt** | AP2's *receipt* format — a plain JWS (with `iss`/`result`/`reference`), a **different** thing from a mandate. |

## Trust models (one-line recap)

| Mechanism | Question it answers | Where it lives |
|---|---|---|
| **`kid`** (key ring) | "is the **root** trusted?" → look up the key in a local list | JWS header |
| **`x5c`** (cert chain) | "is the **root** trusted?" → chain it up to a trusted root CA | JWS header |
| **`cnf`** (delegation) | "who may sign the **next** hop?" → the named public key | SD-JWT payload |
| **`iss`** (not used) | "what name claims to have issued this?" → a label only; needs a JWKS fetch to be useful | — |

## RFCs referenced

| RFC | Topic |
|---|---|
| 7515 | JWS |
| 7517 | JWK |
| 7518 | JWA (defines ES256, HS256) |
| 7519 | JWT |
| 7638 | JWK Thumbprint |
| 7800 | `cnf` / proof-of-possession |
| 5280 | X.509 certificates |
| 4648 §5 | base64url |
| IETF OAuth SD-JWT | Selective-Disclosure JWT (and KB-SD-JWT) |
