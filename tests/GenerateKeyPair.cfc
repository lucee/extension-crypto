component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateKeyPair", function() {

			it( "generates RSA-2048 key pair in PKCS8 format by default", function() {
				var keyPair = GenerateKeyPair( "RSA" );

				expect( keyPair ).toBeStruct();
				expect( keyPair ).toHaveKey( "private" );
				expect( keyPair ).toHaveKey( "public" );
				// Default is PKCS#8 format
				expect( keyPair.private ).toInclude( "-----BEGIN PRIVATE KEY-----" );
				expect( keyPair.public ).toInclude( "-----BEGIN PUBLIC KEY-----" );
			});

			it( "generates RSA-4096 key pair", function() {
				var keyPair = GenerateKeyPair( "RSA-4096" );

				expect( keyPair.private ).toInclude( "-----BEGIN PRIVATE KEY-----" );
				expect( keyPair.public ).toInclude( "-----BEGIN PUBLIC KEY-----" );
			});

			it( "generates P-256 EC key pair", function() {
				var keyPair = GenerateKeyPair( "P-256" );

				expect( keyPair.private ).toInclude( "-----BEGIN PRIVATE KEY-----" );
				expect( keyPair.public ).toInclude( "-----BEGIN PUBLIC KEY-----" );
			});

			it( "generates P-384 EC key pair", function() {
				var keyPair = GenerateKeyPair( "P-384" );

				expect( keyPair.private ).toInclude( "-----BEGIN PRIVATE KEY-----" );
				expect( keyPair.public ).toInclude( "-----BEGIN PUBLIC KEY-----" );
			});

			it( "generates Ed25519 key pair", function() {
				var keyPair = GenerateKeyPair( "Ed25519" );

				expect( keyPair.private ).toInclude( "-----BEGIN PRIVATE KEY-----" );
				expect( keyPair.public ).toInclude( "-----BEGIN PUBLIC KEY-----" );
			});

			it( "supports traditional format for RSA", function() {
				var keyPair = GenerateKeyPair( "RSA", { format: "traditional" } );

				expect( keyPair.private ).toInclude( "-----BEGIN RSA PRIVATE KEY-----" );
			});

			it( "supports traditional format for EC", function() {
				var keyPair = GenerateKeyPair( "P-256", { format: "traditional" } );

				expect( keyPair.private ).toInclude( "-----BEGIN EC PRIVATE KEY-----" );
			});

			it( "errors on traditional format for Ed25519", function() {
				expect( function() {
					GenerateKeyPair( "Ed25519", { format: "traditional" } );
				}).toThrow();
			});

			it( "supports Base64 output format", function() {
				var keyPair = GenerateKeyPair( "RSA-2048", { format: "Base64" } );

				expect( keyPair.private ).notToInclude( "-----BEGIN" );
				expect( keyPair.public ).notToInclude( "-----BEGIN" );
				// Should be valid Base64
				expect( function() {
					binaryDecode( keyPair.private, "base64" );
					binaryDecode( keyPair.public, "base64" );
				}).notToThrow();
			});

			it( "supports DER output format", function() {
				var keyPair = GenerateKeyPair( "RSA-2048", { format: "DER" } );

				expect( isBinary( keyPair.private ) ).toBeTrue();
				expect( isBinary( keyPair.public ) ).toBeTrue();
			});

		});

	}

}
