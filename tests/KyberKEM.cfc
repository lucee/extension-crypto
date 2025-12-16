component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {
		describe( "Kyber Key Encapsulation Mechanism", function() {

			it( "can encapsulate and decapsulate with Kyber768", function() {
				// Generate Kyber key pair
				var keys = GenerateKeyPair( "Kyber768" );

				// Sender encapsulates using recipient's public key
				var encapResult = KyberEncapsulate( keys.public );

				expect( encapResult ).toBeStruct();
				expect( encapResult ).toHaveKey( "sharedSecret" );
				expect( encapResult ).toHaveKey( "ciphertext" );
				expect( isBinary( encapResult.sharedSecret ) ).toBeTrue();
				expect( len( encapResult.ciphertext ) ).toBeGT( 0 );

				// Recipient decapsulates using their private key
				var sharedSecret = KyberDecapsulate( keys.private, encapResult.ciphertext );

				expect( isBinary( sharedSecret ) ).toBeTrue();
				// Both parties should have the same shared secret
				expect( binaryEncode( sharedSecret, "base64" ) )
					.toBe( binaryEncode( encapResult.sharedSecret, "base64" ) );
			});

			it( "can encapsulate and decapsulate with default Kyber", function() {
				var keys = GenerateKeyPair( "Kyber" );

				var encapResult = KyberEncapsulate( keys.public );
				var sharedSecret = KyberDecapsulate( keys.private, encapResult.ciphertext );

				expect( binaryEncode( sharedSecret, "base64" ) )
					.toBe( binaryEncode( encapResult.sharedSecret, "base64" ) );
			});

			it( "can encapsulate and decapsulate with ML-KEM-768 alias", function() {
				var keys = GenerateKeyPair( "ML-KEM-768" );

				var encapResult = KyberEncapsulate( keys.public );
				var sharedSecret = KyberDecapsulate( keys.private, encapResult.ciphertext );

				expect( binaryEncode( sharedSecret, "base64" ) )
					.toBe( binaryEncode( encapResult.sharedSecret, "base64" ) );
			});

			it( "can encapsulate and decapsulate with Kyber512", function() {
				var keys = GenerateKeyPair( "Kyber512" );

				var encapResult = KyberEncapsulate( keys.public );
				var sharedSecret = KyberDecapsulate( keys.private, encapResult.ciphertext );

				expect( binaryEncode( sharedSecret, "base64" ) )
					.toBe( binaryEncode( encapResult.sharedSecret, "base64" ) );
			});

			it( "can encapsulate and decapsulate with Kyber1024", function() {
				var keys = GenerateKeyPair( "Kyber1024" );

				var encapResult = KyberEncapsulate( keys.public );
				var sharedSecret = KyberDecapsulate( keys.private, encapResult.ciphertext );

				expect( binaryEncode( sharedSecret, "base64" ) )
					.toBe( binaryEncode( encapResult.sharedSecret, "base64" ) );
			});

			it( "produces different ciphertexts each time", function() {
				var keys = GenerateKeyPair( "Kyber768" );

				var result1 = KyberEncapsulate( keys.public );
				var result2 = KyberEncapsulate( keys.public );

				// Ciphertexts should be different (randomized)
				expect( result1.ciphertext ).notToBe( result2.ciphertext );

				// But both should decapsulate to working shared secrets
				var secret1 = KyberDecapsulate( keys.private, result1.ciphertext );
				var secret2 = KyberDecapsulate( keys.private, result2.ciphertext );

				expect( binaryEncode( secret1, "base64" ) )
					.toBe( binaryEncode( result1.sharedSecret, "base64" ) );
				expect( binaryEncode( secret2, "base64" ) )
					.toBe( binaryEncode( result2.sharedSecret, "base64" ) );
			});

			it( "can use shared secret for AES encryption", function() {
				var keys = GenerateKeyPair( "Kyber768" );

				// Sender side
				var encapResult = KyberEncapsulate( keys.public );
				var senderKey = binaryEncode( encapResult.sharedSecret, "base64" );
				var plaintext = "Hello, quantum-safe world!";
				var encrypted = Encrypt( plaintext, senderKey, "AES/CBC/PKCS5Padding", "Base64" );

				// Recipient side
				var sharedSecret = KyberDecapsulate( keys.private, encapResult.ciphertext );
				var recipientKey = binaryEncode( sharedSecret, "base64" );
				var decrypted = Decrypt( encrypted, recipientKey, "AES/CBC/PKCS5Padding", "Base64" );

				expect( decrypted ).toBe( plaintext );
			});

			it( "fails with wrong private key", function() {
				var keys1 = GenerateKeyPair( "Kyber768" );
				var keys2 = GenerateKeyPair( "Kyber768" );

				var encapResult = KyberEncapsulate( keys1.public );

				// Try to decapsulate with wrong key - should produce different secret
				var wrongSecret = KyberDecapsulate( keys2.private, encapResult.ciphertext );

				expect( binaryEncode( wrongSecret, "base64" ) )
					.notToBe( binaryEncode( encapResult.sharedSecret, "base64" ) );
			});

			it( "rejects non-Kyber keys", function() {
				var rsaKeys = GenerateKeyPair( "RSA-2048" );

				expect( function() {
					KyberEncapsulate( rsaKeys.public );
				}).toThrow();

				expect( function() {
					KyberDecapsulate( rsaKeys.private, "dummyciphertext" );
				}).toThrow();
			});

		});
	}

}
