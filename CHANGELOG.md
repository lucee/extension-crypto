# Changelog

## [1.0.0.1-SNAPSHOT] - 2026-04-13

- CBOR encode/decode functions (CborEncode, CborDecode, CborToJson, JsonToCbor)
- COSE key conversion functions (KeyToCose, CoseToKey) for WebAuthn/Passkey credential handling
- Extension logo

### Fixed

- CoseToKey now always returns a struct with 'public' key (and 'private' when present)
- Ed25519 PKCS#8 private key wrapping had incorrect ASN.1 SEQUENCE length
- PEM parsing of EC private keys without embedded public key info
- Keystore tests no longer leave artifacts in the repo

## [1.0.0.0-SNAPSHOT] - 2026-04-07

- Initial release with cryptographic functions for Lucee
- Key generation: GenerateKeyPair (RSA, EC, Ed25519, Kyber)
- Hashing: Argon2, BCrypt, SCrypt, Blake2b/Blake3
- JWT: JwtSign, JwtVerify, JwtDecode
- JWK: JwkToKey, KeyToJwk
- TOTP/HOTP one-time passwords
- HKDF key derivation
- Digital signatures: GenerateSignature, VerifySignature
- Certificate operations: GenerateCSR, CertificateInfo
- PEM conversion: KeyToPem, PemToKey
- Keystore operations: GenerateKeystore, KeystoreList, GetKeyPairFromKeystore
- Kyber KEM: KyberEncapsulate, KyberDecapsulate
- Base64URL encode/decode
