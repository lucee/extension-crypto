component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateArgon2Hash", function() {

			it( "generates a valid Argon2 hash with defaults", function() {
				var hash = GenerateArgon2Hash( "password" );

				expect( hash ).toBeString();
				expect( hash ).toMatch( "^\$argon2" );
			});

			it( "generates argon2i hash", function() {
				var hash = GenerateArgon2Hash( "password", "argon2i" );

				expect( hash ).toInclude( "$argon2i$" );
			});

			it( "generates argon2id hash", function() {
				var hash = GenerateArgon2Hash( "password", "argon2id" );

				expect( hash ).toInclude( "$argon2id$" );
			});

			it( "generates different hashes for same input", function() {
				var hash1 = GenerateArgon2Hash( "password" );
				var hash2 = GenerateArgon2Hash( "password" );

				expect( hash1 ).notToBe( hash2 );
			});

		});

		describe( "Argon2CheckHash", function() {

			it( "verifies correct password", function() {
				var hash = GenerateArgon2Hash( "mypassword" );
				var result = Argon2CheckHash( "mypassword", hash );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect password", function() {
				var hash = GenerateArgon2Hash( "mypassword" );
				var result = Argon2CheckHash( "wrongpassword", hash );

				expect( result ).toBeFalse();
			});

			it( "handles invalid hash gracefully", function() {
				var result = Argon2CheckHash( "password", "invalid-hash" );

				expect( result ).toBeFalse();
			});

		});

		describe( "VerifyArgon2Hash alias", function() {

			it( "works as alias for Argon2CheckHash", function() {
				var hash = GenerateArgon2Hash( "password" );
				var result = VerifyArgon2Hash( "password", hash );

				expect( result ).toBeTrue();
			});

		});

	}

}
