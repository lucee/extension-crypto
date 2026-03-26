/**
 * Tests for BCryptVerify() — the preferred BCrypt verification function.
 *
 * History:
 *   - VerifyBCryptHash() was the original name, now deprecated.
 *   - BCryptVerify() replaces it, consistent with Argon2Verify() / SCryptVerify().
 *   - Existing tests for the deprecated name remain in tests/BCrypt.cfc.
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "BCryptVerify", function() {

			it( "verifies correct password", function() {
				var hash = BCryptHash( "mypassword" );
				var result = BCryptVerify( "mypassword", hash );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect password", function() {
				var hash = BCryptHash( "mypassword" );
				var result = BCryptVerify( "wrongpassword", hash );

				expect( result ).toBeFalse();
			});

			it( "handles invalid hash gracefully", function() {
				var result = BCryptVerify( "password", "invalid-hash" );

				expect( result ).toBeFalse();
			});

		});

		describe( "BCryptVerify throwOnError", function() {

			it( "returns false for invalid hash by default", function() {
				var result = BCryptVerify( "password", "not-a-hash" );
				expect( result ).toBeFalse();
			});

			it( "throws on invalid hash when throwOnError is true", function() {
				expect( function() {
					BCryptVerify( "password", "not-a-hash", true );
				}).toThrow();
			});

		});

	}

}
