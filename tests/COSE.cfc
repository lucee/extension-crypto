component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "KeyToCose / CoseToKey roundtrip", function() {

			it( "roundtrips EC P-256 public key", function() {
				var keyPair = GenerateKeyPair( "P-256" );

				var cose = KeyToCose( keyPair );

				expect( isStruct( cose ) ).toBeTrue();
				expect( cose[ "1" ] ).toBe( 2 );   // kty = EC2
				expect( cose[ "3" ] ).toBe( -7 );   // alg = ES256
				expect( cose[ "-1" ] ).toBe( 1 );   // crv = P-256
				expect( isBinary( cose[ "-2" ] ) ).toBeTrue(); // x coordinate
				expect( isBinary( cose[ "-3" ] ) ).toBeTrue(); // y coordinate

				// Convert back and verify signature
				var pubKey = CoseToKey( cose );

				var sig = GenerateSignature(
					data = "test data",
					privateKey = keyPair.private,
					algorithm = "SHA256withECDSA"
				);
				var isValid = VerifySignature(
					data = "test data",
					signature = sig,
					publicKey = KeyToPem( pubKey ),
					algorithm = "SHA256withECDSA"
				);

				expect( isValid ).toBeTrue();
			});

			it( "roundtrips EC P-384 public key", function() {
				var keyPair = GenerateKeyPair( "P-384" );

				var cose = KeyToCose( keyPair );

				expect( cose[ "1" ] ).toBe( 2 );    // kty = EC2
				expect( cose[ "3" ] ).toBe( -35 );   // alg = ES384
				expect( cose[ "-1" ] ).toBe( 2 );   // crv = P-384

				var pubKey = CoseToKey( cose );

				var sig = GenerateSignature(
					data = "test data",
					privateKey = keyPair.private,
					algorithm = "SHA384withECDSA"
				);
				var isValid = VerifySignature(
					data = "test data",
					signature = sig,
					publicKey = KeyToPem( pubKey ),
					algorithm = "SHA384withECDSA"
				);

				expect( isValid ).toBeTrue();
			});

			it( "roundtrips EC P-521 public key", function() {
				var keyPair = GenerateKeyPair( "P-521" );

				var cose = KeyToCose( keyPair );

				expect( cose[ "1" ] ).toBe( 2 );    // kty = EC2
				expect( cose[ "3" ] ).toBe( -36 );   // alg = ES512
				expect( cose[ "-1" ] ).toBe( 3 );   // crv = P-521

				var pubKey = CoseToKey( cose );

				var sig = GenerateSignature(
					data = "test data",
					privateKey = keyPair.private,
					algorithm = "SHA512withECDSA"
				);
				var isValid = VerifySignature(
					data = "test data",
					signature = sig,
					publicKey = KeyToPem( pubKey ),
					algorithm = "SHA512withECDSA"
				);

				expect( isValid ).toBeTrue();
			});

			it( "roundtrips Ed25519 public key", function() {
				var keyPair = GenerateKeyPair( "Ed25519" );

				var cose = KeyToCose( keyPair );

				expect( cose[ "1" ] ).toBe( 1 );   // kty = OKP
				expect( cose[ "3" ] ).toBe( -8 );   // alg = EdDSA
				expect( cose[ "-1" ] ).toBe( 6 );   // crv = Ed25519
				expect( isBinary( cose[ "-2" ] ) ).toBeTrue(); // x coordinate

				var pubKey = CoseToKey( cose );

				var sig = GenerateSignature(
					data = "test data",
					privateKey = keyPair.private,
					algorithm = "Ed25519"
				);
				var isValid = VerifySignature(
					data = "test data",
					signature = sig,
					publicKey = KeyToPem( pubKey ),
					algorithm = "Ed25519"
				);

				expect( isValid ).toBeTrue();
			});

		});

		describe( "KeyToCose with private keys", function() {

			it( "includes EC private key material when key pair has both keys", function() {
				var keyPair = GenerateKeyPair( "P-256" );

				var cose = KeyToCose( keyPair );

				// Should include -4 (d = private key)
				expect( isBinary( cose[ "-4" ] ) ).toBeTrue();

				// Roundtrip the private key
				var privKey = CoseToKey( cose );

				// Sign with the roundtripped private key
				var sig = GenerateSignature(
					data = "private key test",
					privateKey = KeyToPem( privKey ),
					algorithm = "SHA256withECDSA"
				);
				var isValid = VerifySignature(
					data = "private key test",
					signature = sig,
					publicKey = keyPair.public,
					algorithm = "SHA256withECDSA"
				);

				expect( isValid ).toBeTrue();
			});

			it( "includes Ed25519 private key material", function() {
				var keyPair = GenerateKeyPair( "Ed25519" );

				var cose = KeyToCose( keyPair );

				expect( isBinary( cose[ "-4" ] ) ).toBeTrue();
			});

		});

		describe( "KeyToCose input types", function() {

			it( "accepts PEM string", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var cose = KeyToCose( keyPair.public );

				expect( cose[ "1" ] ).toBe( 2 );
				// Public key only — no -4
				expect( structKeyExists( cose, "-4" ) ).toBeFalse();
			});

		});

		describe( "CoseToKey with CBOR binary input", function() {

			it( "accepts raw CBOR bytes", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var cose = KeyToCose( keyPair );

				// Encode the COSE struct to CBOR
				var cborBytes = CborEncode( cose );

				// CoseToKey should decode CBOR internally
				var pubKey = CoseToKey( cborBytes );

				var sig = GenerateSignature(
					data = "cbor test",
					privateKey = keyPair.private,
					algorithm = "SHA256withECDSA"
				);
				var isValid = VerifySignature(
					data = "cbor test",
					signature = sig,
					publicKey = KeyToPem( pubKey ),
					algorithm = "SHA256withECDSA"
				);

				expect( isValid ).toBeTrue();
			});

		});

		describe( "CoseToKey EC coordinate sizes", function() {

			it( "P-256 x/y coordinates are 32 bytes", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var cose = KeyToCose( keyPair );

				expect( arrayLen( binaryDecode( binaryEncode( cose[ "-2" ], "base64" ), "base64" ) ) ).toBe( 32 );
				expect( arrayLen( binaryDecode( binaryEncode( cose[ "-3" ], "base64" ), "base64" ) ) ).toBe( 32 );
			});

		});

	}

}
