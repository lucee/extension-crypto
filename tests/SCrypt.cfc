component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateSCryptHash", function() {

			it( "generates a valid SCrypt hash", function() {
				var hash = GenerateSCryptHash( "password" );

				expect( hash ).toBeString();
				expect( hash ).toMatch( "^\$scrypt\$ln=\d+,r=\d+,p=\d+\$.+\$.+$" );
			});

			it( "generates different hashes for same input", function() {
				var hash1 = GenerateSCryptHash( "password" );
				var hash2 = GenerateSCryptHash( "password" );

				expect( hash1 ).notToBe( hash2 );
			});

			it( "respects cost parameters", function() {
				// Use lower cost for faster test (N=4096 = ln=12)
				var hash = GenerateSCryptHash( "password", 4096, 4, 1 );

				expect( hash ).toInclude( "ln=12" );
				expect( hash ).toInclude( "r=4" );
				expect( hash ).toInclude( "p=1" );
			});

			it( "validates cost parameter must be power of 2", function() {
				expect( function() {
					GenerateSCryptHash( "password", 1000 );
				}).toThrow();
			});

		});

		describe( "VerifySCryptHash", function() {

			it( "verifies correct password", function() {
				// Use lower cost for faster test
				var hash = GenerateSCryptHash( "mypassword", 4096, 4, 1 );
				var result = VerifySCryptHash( "mypassword", hash );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect password", function() {
				var hash = GenerateSCryptHash( "mypassword", 4096, 4, 1 );
				var result = VerifySCryptHash( "wrongpassword", hash );

				expect( result ).toBeFalse();
			});

			it( "handles invalid hash gracefully", function() {
				var result = VerifySCryptHash( "password", "invalid-hash" );

				expect( result ).toBeFalse();
			});

			it( "handles non-scrypt hash gracefully", function() {
				var result = VerifySCryptHash( "password", "$2a$10$somebcrypthash" );

				expect( result ).toBeFalse();
			});

		});

	}

}
