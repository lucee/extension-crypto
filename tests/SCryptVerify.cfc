/**
 * Tests for SCryptVerify() — the preferred SCrypt verification function.
 *
 * History:
 *   - VerifySCryptHash() was the original name, now deprecated.
 *   - SCryptVerify() replaces it, consistent with Argon2Verify() / BCryptVerify().
 *   - Existing tests for the deprecated name remain in tests/SCrypt.cfc.
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "SCryptVerify", function() {

			it( "verifies correct password", function() {
				// Use lower cost for faster test
				var hash = SCryptHash( "mypassword", 4096, 4, 1 );
				var result = SCryptVerify( "mypassword", hash );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect password", function() {
				var hash = SCryptHash( "mypassword", 4096, 4, 1 );
				var result = SCryptVerify( "wrongpassword", hash );

				expect( result ).toBeFalse();
			});

			it( "handles invalid hash gracefully", function() {
				var result = SCryptVerify( "password", "invalid-hash" );

				expect( result ).toBeFalse();
			});

			it( "handles non-scrypt hash gracefully", function() {
				var result = SCryptVerify( "password", "$2a$10$somebcrypthash" );

				expect( result ).toBeFalse();
			});

		});

		describe( "SCryptVerify throwOnError", function() {

			it( "returns false for invalid hash by default", function() {
				var result = SCryptVerify( "password", "not-a-hash" );
				expect( result ).toBeFalse();
			});

			it( "throws on invalid hash when throwOnError is true", function() {
				expect( function() {
					SCryptVerify( "password", "not-a-hash", true );
				}).toThrow();
			});

		});

	}

}
