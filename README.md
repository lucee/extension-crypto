# Lucee Crypto Extension

[![Java CI](https://github.com/lucee/extension-crypto/actions/workflows/main.yml/badge.svg)](https://github.com/lucee/extension-crypto/actions/workflows/main.yml)

Modern cryptographic functions for Lucee, powered by [BouncyCastle](https://www.bouncycastle.org/download/bouncy-castle-java/) and [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).

**Requires Lucee 7.0.3+** — uses maven-based classloading (no OSGi).

## Installation

Install via Lucee Admin, or pin in your environment:

```bash
LUCEE_EXTENSIONS=org.lucee:crypto-extension:1.0.0.0-SNAPSHOT
```

## Documentation

Full documentation with examples is available at **[docs.lucee.org/categories/crypto](https://docs.lucee.org/categories/crypto.html)**.

### What's Included

- **Key Pairs & Conversion** — RSA, EC (P-256/384/521), EdDSA (Ed25519/Ed448), post-quantum (Kyber, Dilithium). PEM and JWK conversion.
- **JWT** — Sign, verify, and decode JWTs. HMAC, RSA, EC, PSS, EdDSA algorithms. JWKS loading for OAuth2/OIDC.
- **Digital Signatures** — Sign and verify data with asymmetric keys.
- **Password Hashing** — Argon2 (OWASP defaults), BCrypt, SCrypt.
- **TOTP / HOTP** — Two-factor authentication (RFC 6238 / RFC 4226).
- **Certificates & Keystores** — Self-signed certs, CSRs, PKCS12/JKS keystore management.
- **Blake Hashing** — Blake2b, Blake2s, Blake3.
- **HKDF** — Key derivation (extract-then-expand).
- **Post-Quantum Key Exchange** — ML-KEM/Kyber key encapsulation.
- **CBOR** — Encode/decode CBOR binary format, JSON conversion. COSE key conversion for WebAuthn/passkeys.
- **Base64URL** — URL-safe Base64 encoding/decoding.

### Quick Example

```cfml
// JWT authentication flow
keys = GenerateKeyPair( "Ed25519" );

token = JwtSign(
	claims = { sub: "user123", role: "admin" },
	key = keys.private,
	expiresIn = 3600
);

claims = JwtVerify( token, keys.public );

// Password hashing (Argon2 with OWASP defaults)
hash = Argon2Hash( "mypassword" );
isValid = Argon2Verify( "mypassword", hash );
```

## Technical Details

Maven-based extension using embedded `/maven/` repo layout with `maven=` attribute in the FLD. No OSGi bundles.

## Issues

[Lucee JIRA - Crypto Issues](https://luceeserver.atlassian.net/issues/?jql=labels%20%3D%20crypto)
