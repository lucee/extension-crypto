# Lucee Extension Crypto

[![Java CI](https://github.com/lucee/extension-crypto/actions/workflows/main.yml/badge.svg)](https://github.com/lucee/extension-crypto/actions/workflows/main.yml)

This extension provides modern cryptographic functions for Lucee, powered by [BouncyCastle](https://www.bouncycastle.org/download/bouncy-castle-java/). It includes key pair generation, digital signatures, password hashing, certificate management, and key derivation functions.

It also includes JWT functionality using [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) as it also requires Bouncy Castle.

## Key Pair Generation

Generate cryptographic key pairs for various algorithms including RSA, Elliptic Curve, EdDSA, and post-quantum algorithms.

```cfml
// RSA key pair (default 2048-bit)
keys = GenerateKeyPair( "RSA" );
keys = GenerateKeyPair( "RSA-4096" );

// Elliptic Curve
keys = GenerateKeyPair( "P-256" );
keys = GenerateKeyPair( "P-384" );
keys = GenerateKeyPair( "P-521" );

// EdDSA (modern, fast)
keys = GenerateKeyPair( "Ed25519" );
keys = GenerateKeyPair( "Ed448" );

// Post-quantum (experimental)
keys = GenerateKeyPair( "Kyber768" );
keys = GenerateKeyPair( "Dilithium3" );

// Access the keys
writeOutput( keys.private );
writeOutput( keys.public );

// Validate a key pair matches
isValid = ValidateKeyPair( keys.private, keys.public );
```

### Key Conversion

```cfml
// Convert PEM to Java key object
privateKey = PemToKey( pemString );

// Convert Java key to PEM
pemString = KeyToPem( javaKeyObject );
```

## Digital Signatures

Sign and verify data using asymmetric cryptography.

```cfml
// Generate keys
keys = GenerateKeyPair( "Ed25519" );

// Sign data
signature = GenerateSignature( "data to sign", keys.private );

// Verify signature
isValid = VerifySignature( "data to sign", signature, keys.public );
```

## JSON Web Tokens (JWT)

Create, verify, and decode JWTs using HMAC or asymmetric algorithms.

### Sign a JWT

```cfml
// HMAC (symmetric) - simple shared secret
token = JwtSign(
    claims = { sub: "user123", role: "admin" },
    key = "your-256-bit-secret"
);

// With expiration (seconds from now)
token = JwtSign(
    claims = { sub: "user123" },
    key = "secret",
    expiresIn = 3600    // 1 hour
);

// RSA/EC (asymmetric) - use private key to sign
keys = GenerateKeyPair( "RS256" );
token = JwtSign(
    claims = { sub: "user123" },
    key = keys.private,
    algorithm = "RS256",
    issuer = "https://myapp.com",
    audience = "https://api.myapp.com"
);

// EdDSA (modern, fast)
keys = GenerateKeyPair( "Ed25519" );
token = JwtSign(
    claims = { sub: "user123" },
    key = keys.private,
    algorithm = "EdDSA"
);

// With Key ID for key rotation
token = JwtSign(
    claims = { sub: "user123" },
    key = keys.private,
    algorithm = "RS256",
    kid = "key-2024-01"
);
```

### Verify a JWT

```cfml
// Verify with HMAC secret
claims = JwtVerify( token = token, key = "your-256-bit-secret" );
writeOutput( claims.sub );  // "user123"

// Verify with public key
claims = JwtVerify( token = token, key = keys.public );

// With issuer/audience validation
claims = JwtVerify(
    token = token,
    key = keys.public,
    issuer = "https://myapp.com",
    audience = "https://api.myapp.com"
);

// Restrict allowed algorithms (security best practice)
claims = JwtVerify(
    token = token,
    key = keys.public,
    algorithms = "RS256"           // single algorithm
    // or: algorithms = ["RS256", "RS384"]  // multiple
);

// Clock skew tolerance (seconds) for exp/nbf validation
claims = JwtVerify(
    token = token,
    key = "secret",
    clockSkew = 60    // allow 60 seconds leeway
);

// Non-throwing mode - returns result struct instead of throwing
result = JwtVerify( token = token, key = "secret", throwOnError = false );
if ( result.valid ) {
    writeOutput( result.claims.sub );
} else {
    writeOutput( "Error: " & result.error );
}
```

### Decode a JWT (without verification)

Useful for debugging or when you need to inspect a token before verification.

```cfml
parts = JwtDecode( token );
writeOutput( parts.header.alg );      // "RS256"
writeOutput( parts.payload.sub );     // "user123"
writeOutput( parts.signature );       // base64url signature
```

### Supported JWT Algorithms

| Algorithm | Type | Description |
|-----------|------|-------------|
| `HS256`, `HS384`, `HS512` | HMAC | Symmetric, shared secret |
| `RS256`, `RS384`, `RS512` | RSA | Asymmetric, RSA keys |
| `ES256`, `ES384`, `ES512` | ECDSA | Asymmetric, EC keys (P-256/384/521) |
| `PS256`, `PS384`, `PS512` | RSA-PSS | Asymmetric, RSA-PSS padding |
| `EdDSA` | EdDSA | Asymmetric, Ed25519/Ed448 keys |

## Password Hashing

Secure password hashing with Argon2, BCrypt, and SCrypt.

### Argon2 (recommended for new applications)

```cfml
// Hash a password
hash = GenerateArgon2Hash( "mypassword" );

// With custom parameters
hash = GenerateArgon2Hash(
    input = "mypassword",
    variant = "argon2id",      // argon2i, argon2d, or argon2id
    parallelismFactor = 2,
    memoryCost = 65536,        // KB
    iterations = 3
);

// Verify password
isValid = Argon2CheckHash( "mypassword", hash );
// or
isValid = VerifyArgon2Hash( "mypassword", hash );
```

### BCrypt

```cfml
// Hash with default cost (10)
hash = GenerateBCryptHash( "mypassword" );

// With custom cost
hash = GenerateBCryptHash( "mypassword", 12 );

// Verify
isValid = VerifyBCryptHash( "mypassword", hash );
```

### SCrypt

```cfml
// Hash with defaults
hash = GenerateSCryptHash( "mypassword" );

// With custom parameters
hash = GenerateSCryptHash(
    input = "mypassword",
    costParameter = 16384,     // N (must be power of 2)
    blockSize = 8,             // r
    parallelization = 1        // p
);

// Verify
isValid = VerifySCryptHash( "mypassword", hash );
```

## Certificates

Generate and inspect X.509 certificates.

```cfml
// Generate a self-signed certificate
keys = GenerateKeyPair( "RSA-2048" );
cert = GenerateSelfSignedCertificate(
    keyPair = keys,
    subject = "CN=localhost, O=My Company, C=AU",
    validityDays = 365
);

// Get certificate info
info = CertificateInfo( cert );
writeOutput( info.subject );
writeOutput( info.validFrom );
writeOutput( info.validTo );

// Convert between PEM and Java objects
certObj = PemToCertificate( pemString );
pemString = CertificateToPem( certObj );
```

## Keystores

Create and manage Java keystores (PKCS12, JKS).

```cfml
// Generate a new keystore with key pair and certificate
GenerateKeystore(
    keystore = "/path/to/keystore.p12",
    keystorePassword = "changeit",
    alias = "mykey",
    algorithm = "RSA-2048",
    subject = "CN=localhost"
);

// List aliases in a keystore
aliases = KeystoreList( "/path/to/keystore.p12", "changeit" );

// Extract key pair from keystore
keys = GetKeyPairFromKeystore(
    keystore = "/path/to/keystore.p12",
    keystorePassword = "changeit",
    keystoreAlias = "mykey"
);
// Returns: { private: "...", public: "...", certificate: "..." }
```

## Modern Hashing (Blake)

Fast, secure hashing with the Blake family of algorithms.

```cfml
// Blake2b (optimized for 64-bit, faster than SHA-256)
hash = GenerateBlake2bHash( "data" );
hash = GenerateBlake2bHash( "data", 32 );              // custom output length
hash = GenerateBlake2bHash( "data", 32, keyBytes );    // keyed (MAC)

// Blake2s (optimized for 32-bit/embedded)
hash = GenerateBlake2sHash( "data" );

// Blake3 (latest, very fast, parallelizable)
hash = GenerateBlake3Hash( "data" );
hash = GenerateBlake3Hash( "data", 64 );                        // arbitrary output length
hash = GenerateBlake3Hash( "data", 32, key32bytes );            // keyed mode
hash = GenerateBlake3Hash( "data", 32, "", "MyApp context" );   // key derivation mode
```

## Key Derivation (HKDF)

Derive keys from shared secrets using HKDF (used in TLS 1.3, Signal Protocol).

```cfml
// One-shot key derivation
derivedKey = GenerateHKDFKey(
    algorithm = "SHA256",
    inputKeyMaterial = sharedSecret,
    salt = saltBytes,
    info = "encryption key",
    outputLength = 32
);

// Two-phase (extract then expand multiple keys)
prk = HKDFExtract( "SHA256", salt, sharedSecret );
encryptionKey = HKDFExpand( "SHA256", prk, "encryption", 32 );
authKey = HKDFExpand( "SHA256", prk, "authentication", 32 );
```

## Base64URL Encoding

URL-safe Base64 encoding (used in JWTs, etc.).

```cfml
// Encode
encoded = Base64UrlEncode( "Hello World" );
encoded = Base64UrlEncode( binaryData );

// Decode to binary
binary = Base64UrlDecode( encoded );

// Decode to string
str = Base64UrlDecode( encoded, "UTF-8" );
```

## Post-Quantum Key Exchange (ML-KEM/Kyber)

ML-KEM (formerly Kyber) provides quantum-resistant key encapsulation for establishing shared secrets.
Both `Kyber` and `ML-KEM` naming conventions are supported.

```cfml
// Generate key pair (Kyber768 and ML-KEM-768 are equivalent)
keys = GenerateKeyPair( "Kyber768" );
// or: keys = GenerateKeyPair( "ML-KEM-768" );

// Sender: encapsulate using recipient's public key
result = KyberEncapsulate( keys.public );
// result.sharedSecret = binary (use for encryption)
// result.ciphertext = string (send to recipient)

// Recipient: decapsulate using their private key
sharedSecret = KyberDecapsulate( keys.private, result.ciphertext );
// sharedSecret matches result.sharedSecret

// Use shared secret for symmetric encryption
encrypted = Encrypt( "secret message", binaryEncode( sharedSecret, "base64" ), "AES", "Base64" );
```

## Supported Algorithms

### Key Pair Algorithms

| Algorithm | Description |
|-----------|-------------|
| `RSA`, `RSA-2048`, `RSA-4096` | RSA with specified key size |
| `EC`, `P-256`, `P-384`, `P-521` | ECDSA with NIST curves |
| `Ed25519`, `Ed448` | EdDSA (modern, fast signatures) |
| `Kyber512`, `Kyber768`, `Kyber1024` | Post-quantum key encapsulation (ML-KEM) |
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Same as Kyber (NIST standard name) |
| `Dilithium2`, `Dilithium3`, `Dilithium5` | Post-quantum signatures |

### Hash Algorithms for HKDF

| Algorithm | Output Size |
|-----------|-------------|
| `SHA256` | 32 bytes |
| `SHA384` | 48 bytes |
| `SHA512` | 64 bytes |

## Requirements

- Lucee 6.x or later
- Java 11 or later

## Technical Details

This extension uses [BouncyCastle](https://www.bouncycastle.org/) for cryptographic operations.

## Issues

[Lucee JIRA - Crypto Issues](https://luceeserver.atlassian.net/issues/?jql=labels%20%3D%20crypto)
