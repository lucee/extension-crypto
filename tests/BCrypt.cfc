component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateBCryptHash", function() {

			it( "generates a valid BCrypt hash", function() {
				var hash = GenerateBCryptHash( "password" );

				expect( hash ).toBeString();
				expect( hash ).toMatch( "^\$2[aby]?\$\d{2}\$.{53}$" );
			});

			it( "generates different hashes for same input", function() {
				var hash1 = GenerateBCryptHash( "password" );
				var hash2 = GenerateBCryptHash( "password" );

				expect( hash1 ).notToBe( hash2 );
			});

			it( "respects cost parameter", function() {
				var hash = GenerateBCryptHash( "password", 4 );

				expect( hash ).toInclude( "$04$" );
			});

		});

		describe( "VerifyBCryptHash", function() {

			it( "verifies correct password", function() {
				var hash = GenerateBCryptHash( "mypassword" );
				var result = VerifyBCryptHash( "mypassword", hash );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect password", function() {
				var hash = GenerateBCryptHash( "mypassword" );
				var result = VerifyBCryptHash( "wrongpassword", hash );

				expect( result ).toBeFalse();
			});

			it( "handles invalid hash gracefully", function() {
				var result = VerifyBCryptHash( "password", "invalid-hash" );

				expect( result ).toBeFalse();
			});

		});

	}

}
