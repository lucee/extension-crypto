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

		describe( "GenerateArgon2Hash backwards compatibility with extension-argon2", function() {

			it( "default variant is argon2i for compat", function() {
				// extension-argon2 defaulted to argon2i
				var hash = GenerateArgon2Hash( "password" );
				expect( hash ).toInclude( "$argon2i$" );
			});

			it( "default params match extension-argon2 FLD defaults", function() {
				// extension-argon2 FLD: parallelism=1, memory=8, iterations=1
				var hash = GenerateArgon2Hash( "test" );
				// parse the PHC string to check params
				// format: $argon2i$v=19$m=8,t=1,p=1$salt$hash
				expect( hash ).toMatch( "m=8," );
				expect( hash ).toMatch( ",p=1\$" );
			});

			it( "verifies hashes generated with old extension-argon2 defaults", function() {
				// generate with explicit old defaults to simulate extension-argon2 output
				var hash = GenerateArgon2Hash( "password", "argon2i", 1, 8, 1 );
				expect( Argon2CheckHash( "password", hash ) ).toBeTrue();
			});

			it( "supports argon2d variant", function() {
				var hash = GenerateArgon2Hash( "password", "argon2d" );
				expect( hash ).toInclude( "$argon2d$" );
				expect( Argon2CheckHash( "password", hash ) ).toBeTrue();
			});

		});

		describe( "GenerateArgon2Hash parameter validation", function() {

			it( "rejects parallelism outside 1-10 range", function() {
				expect( function() {
					GenerateArgon2Hash( "test", "argon2i", 11, 8, 1 );
				}).toThrow();
			});

			it( "rejects memory outside 8-100000 range", function() {
				expect( function() {
					GenerateArgon2Hash( "test", "argon2i", 1, 7, 1 );
				}).toThrow();
			});

			it( "rejects iterations outside 1-20 range", function() {
				expect( function() {
					GenerateArgon2Hash( "test", "argon2i", 1, 8, 0 );
				}).toThrow();
			});

			it( "rejects unknown variant", function() {
				expect( function() {
					GenerateArgon2Hash( "test", "argon2z" );
				}).toThrow();
			});

		});

		describe( "Argon2CheckHash throwOnError", function() {

			it( "returns false for invalid hash by default", function() {
				var result = Argon2CheckHash( "password", "not-a-hash" );
				expect( result ).toBeFalse();
			});

			it( "throws on invalid hash when throwOnError is true", function() {
				expect( function() {
					Argon2CheckHash( "password", "not-a-hash", true );
				}).toThrow();
			});

			it( "still returns false for wrong password with throwOnError", function() {
				var hash = GenerateArgon2Hash( "correct", "argon2i", 1, 8, 1 );
				var result = Argon2CheckHash( "wrong", hash, true );
				expect( result ).toBeFalse();
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
