component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "PemToKey", function() {

			it( "parses a private key PEM", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var key = PemToKey( keyPair.private );

				expect( isInstanceOf( key, "java.security.PrivateKey" ) ).toBeTrue();
			});

			it( "parses a public key PEM", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var key = PemToKey( keyPair.public );

				expect( isInstanceOf( key, "java.security.PublicKey" ) ).toBeTrue();
			});

		});

		describe( "KeyToPem", function() {

			it( "converts private key back to PEM", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var key = PemToKey( keyPair.private );
				var pem = KeyToPem( key );

				// KeyToPem uses traditional format by default
				expect( pem ).toMatch( "-----BEGIN (RSA )?PRIVATE KEY-----" );
			});

			it( "converts public key back to PEM", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var key = PemToKey( keyPair.public );
				var pem = KeyToPem( key );

				expect( pem ).toInclude( "-----BEGIN PUBLIC KEY-----" );
			});

		});

		describe( "ValidateKeyPair", function() {

			it( "validates matching key pair", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var isValid = ValidateKeyPair( keyPair.private, keyPair.public );

				expect( isValid ).toBeTrue();
			});

			it( "rejects mismatched key pair", function() {
				var keyPair1 = GenerateKeyPair( "RSA-2048" );
				var keyPair2 = GenerateKeyPair( "RSA-2048" );
				var isValid = ValidateKeyPair( keyPair1.private, keyPair2.public );

				expect( isValid ).toBeFalse();
			});

			it( "validates EC key pair", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var isValid = ValidateKeyPair( keyPair.private, keyPair.public );

				expect( isValid ).toBeTrue();
			});

		});

	}

}
