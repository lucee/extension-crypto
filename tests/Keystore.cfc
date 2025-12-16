component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	variables.testDir = getDirectoryFromPath( getCurrentTemplatePath() ) & "keystore-test/";
	variables.keystorePath = variables.testDir & "test.p12";
	variables.keystorePassword = "testpass123";
	variables.alias = "testkey";

	function beforeAll() {
		// Cleanup any previous test artifacts
		if ( directoryExists( variables.testDir ) ) {
			directoryDelete( variables.testDir, true );
		}
		directoryCreate( variables.testDir );

		// Generate a test keystore using our own function
		GenerateKeystore(
			variables.keystorePath,
			variables.keystorePassword,
			variables.alias,
			"RSA-2048",
			"CN=Test, OU=Test, O=Test, L=Test, ST=Test, C=AU"
		);

		// Add a second key (EC) to the same keystore
		GenerateKeystore(
			variables.testDir & "test2.p12",
			variables.keystorePassword,
			"secondkey",
			"P-256",
			"CN=Second, OU=Test, O=Test, L=Test, ST=Test, C=AU"
		);
	}

	function run( testResults, testBox ) {

		describe( "GenerateKeystore", function() {

			it( "creates a PKCS12 keystore with RSA key", function() {
				expect( fileExists( variables.keystorePath ) ).toBeTrue();

				var aliases = KeystoreList( variables.keystorePath, variables.keystorePassword );
				expect( aliases ).toInclude( "testkey" );
			});

			it( "creates a keystore with EC key", function() {
				var ecPath = variables.testDir & "test2.p12";
				expect( fileExists( ecPath ) ).toBeTrue();

				var aliases = KeystoreList( ecPath, variables.keystorePassword );
				expect( aliases ).toInclude( "secondkey" );
			});

		});

		describe( "KeystoreList", function() {

			it( "lists aliases in a keystore", function() {
				var aliases = KeystoreList( variables.keystorePath, variables.keystorePassword );

				expect( aliases ).toBeArray();
				expect( aliases ).toHaveLength( 1 );
				expect( aliases ).toInclude( "testkey" );
			});

			it( "auto-detects PKCS12 type from .p12 extension", function() {
				var aliases = KeystoreList( variables.keystorePath, variables.keystorePassword );

				expect( aliases ).toBeArray();
			});

			it( "throws for wrong password", function() {
				expect( function() {
					KeystoreList( variables.keystorePath, "wrongpassword" );
				}).toThrow();
			});

			it( "throws for non-existent file", function() {
				expect( function() {
					KeystoreList( "/nonexistent/keystore.p12", "password" );
				}).toThrow();
			});

		});

		describe( "GetKeyPairFromKeystore", function() {

			it( "extracts RSA key pair and certificate", function() {
				var result = GetKeyPairFromKeystore(
					variables.keystorePath,
					variables.keystorePassword,
					variables.keystorePassword,
					variables.alias
				);

				expect( result ).toBeStruct();
				expect( result ).toHaveKey( "private" );
				expect( result ).toHaveKey( "public" );
				expect( result ).toHaveKey( "certificate" );

				expect( result.private ).toInclude( "BEGIN PRIVATE KEY" );
				expect( result.public ).toInclude( "BEGIN PUBLIC KEY" );
				expect( result.certificate ).toInclude( "BEGIN CERTIFICATE" );
			});

			it( "extracts EC key pair", function() {
				var ecPath = variables.testDir & "test2.p12";
				var result = GetKeyPairFromKeystore(
					ecPath,
					variables.keystorePassword,
					variables.keystorePassword,
					"secondkey"
				);

				expect( result.private ).toInclude( "BEGIN PRIVATE KEY" );
				expect( result.public ).toInclude( "BEGIN PUBLIC KEY" );
			});

			it( "throws for non-existent alias", function() {
				expect( function() {
					GetKeyPairFromKeystore(
						variables.keystorePath,
						variables.keystorePassword,
						variables.keystorePassword,
						"nonexistent"
					);
				}).toThrow();
			});

			it( "throws for wrong password", function() {
				expect( function() {
					GetKeyPairFromKeystore(
						variables.keystorePath,
						"wrongpassword",
						"wrongpassword",
						variables.alias
					);
				}).toThrow();
			});

		});

	}

}
