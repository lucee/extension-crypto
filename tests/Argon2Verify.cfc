/**
 * Tests for Argon2Verify() — the preferred Argon2 verification function.
 *
 * History:
 *   - Argon2CheckHash() was the original name (from extension-argon2), now deprecated.
 *   - VerifyArgon2Hash() was an alias (from extension-argon2), now deprecated.
 *   - Argon2Verify() replaces both, consistent with BCryptVerify() / SCryptVerify().
 *   - Existing tests for the deprecated names remain in tests/Argon2.cfc.
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "Argon2Verify", function() {

			it( "verifies correct password", function() {
				// Use low params for speed
				var hash = Argon2Hash( "mypassword", "argon2id", 1, 8, 1 );
				var result = Argon2Verify( "mypassword", hash );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect password", function() {
				var hash = Argon2Hash( "mypassword", "argon2id", 1, 8, 1 );
				var result = Argon2Verify( "wrongpassword", hash );

				expect( result ).toBeFalse();
			});

			it( "handles invalid hash gracefully", function() {
				var result = Argon2Verify( "password", "invalid-hash" );

				expect( result ).toBeFalse();
			});

		});

		describe( "Argon2Verify throwOnError", function() {

			it( "returns false for invalid hash by default", function() {
				var result = Argon2Verify( "password", "not-a-hash" );
				expect( result ).toBeFalse();
			});

			it( "throws on invalid hash when throwOnError is true", function() {
				expect( function() {
					Argon2Verify( "password", "not-a-hash", true );
				}).toThrow();
			});

			it( "still returns false for wrong password with throwOnError", function() {
				var hash = Argon2Hash( "correct", "argon2id", 1, 8, 1 );
				var result = Argon2Verify( "wrong", hash, true );
				expect( result ).toBeFalse();
			});

		});

		describe( "Argon2Verify cross-compatibility", function() {

			it( "verifies hashes from all three variants", function() {
				var hashI = Argon2Hash( "password", "argon2i", 1, 8, 1 );
				var hashD = Argon2Hash( "password", "argon2d", 1, 8, 1 );
				var hashID = Argon2Hash( "password", "argon2id", 1, 8, 1 );

				expect( Argon2Verify( "password", hashI ) ).toBeTrue();
				expect( Argon2Verify( "password", hashD ) ).toBeTrue();
				expect( Argon2Verify( "password", hashID ) ).toBeTrue();
			});

			it( "verifies hashes created with old extension-argon2 defaults", function() {
				// Simulate old extension-argon2 output: argon2i, parallelism=1, memory=8, iterations=1
				var hash = GenerateArgon2Hash( "password", "argon2i", 1, 8, 1 );
				expect( Argon2Verify( "password", hash ) ).toBeTrue();
			});

		});

	}

}
