/**
 * Tests for TOTP functions: TOTPSecret(), TOTPGenerateUri(), TOTPVerify().
 *
 * TOTP (Time-based One-Time Password, RFC 6238) builds on HOTP (RFC 4226)
 * by deriving the counter from the current time. These functions provide
 * the building blocks for two-factor authentication (2FA).
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "TOTPSecret", function() {

			it( "generates a Base32-encoded secret", function() {
				var secret = TOTPSecret();

				expect( secret ).toBeString();
				// Base32 uses A-Z and 2-7 only
				expect( secret ).toMatch( "^[A-Z2-7]+$" );
			});

			it( "default length produces 32-char Base32 string (20 bytes)", function() {
				var secret = TOTPSecret();

				// 20 bytes = 160 bits, Base32 encodes 5 bits per char = 32 chars
				expect( len( secret ) ).toBe( 32 );
			});

			it( "supports custom length", function() {
				var secret = TOTPSecret( 32 );

				// 32 bytes = 256 bits / 5 = 52 chars (rounded up)
				expect( len( secret ) ).toBeGT( 32 );
			});

			it( "generates unique secrets", function() {
				var s1 = TOTPSecret();
				var s2 = TOTPSecret();

				expect( s1 ).notToBe( s2 );
			});

			it( "rejects length below 16", function() {
				expect( function() {
					TOTPSecret( 8 );
				}).toThrow();
			});

			it( "rejects length above 128", function() {
				expect( function() {
					TOTPSecret( 200 );
				}).toThrow();
			});

		});

		describe( "TOTPGenerateUri", function() {

			it( "generates a valid otpauth URI", function() {
				var secret = TOTPSecret();
				var uri = TOTPGenerateUri( secret, "user@example.com", "MyApp" );

				expect( uri ).toMatch( "^otpauth://totp/" );
				expect( uri ).toInclude( "secret=" & secret );
				expect( uri ).toInclude( "issuer=MyApp" );
				expect( uri ).toInclude( "algorithm=SHA1" );
				expect( uri ).toInclude( "digits=6" );
				expect( uri ).toInclude( "period=30" );
			});

			it( "URL-encodes special characters in issuer and account", function() {
				var secret = TOTPSecret();
				var uri = TOTPGenerateUri( secret, "user@example.com", "My App & Co" );

				expect( uri ).toInclude( "My+App+%26+Co" );
			});

			it( "supports custom options", function() {
				var secret = TOTPSecret( 32 );
				var uri = TOTPGenerateUri( secret, "user@example.com", "MyApp", {
					digits: 8,
					period: 60,
					algorithm: "SHA256"
				});

				expect( uri ).toInclude( "digits=8" );
				expect( uri ).toInclude( "period=60" );
				expect( uri ).toInclude( "algorithm=SHA256" );
			});

		});

		describe( "TOTPVerify", function() {

			it( "verifies a code generated from the same secret using HOTP at the current time counter", function() {
				// Generate a secret and produce a code at the current time step
				var secret = TOTPSecret();
				var currentCounter = int( getTickCount() / 1000 / 30 );
				var code = HOTPGenerate( secret, currentCounter );

				expect( TOTPVerify( secret, code ) ).toBeTrue();
			});

			it( "rejects an incorrect code", function() {
				var secret = TOTPSecret();

				expect( TOTPVerify( secret, "000000" ) ).toBeFalse();
			});

			it( "respects the window parameter for clock skew", function() {
				var secret = TOTPSecret();
				// Generate code for the previous time step
				var prevCounter = int( getTickCount() / 1000 / 30 ) - 1;
				var code = HOTPGenerate( secret, prevCounter );

				// window=1 (default) should accept previous step
				expect( TOTPVerify( secret, code ) ).toBeTrue();

				// window=0 may or may not accept depending on timing, but a code
				// from 2 steps ago should fail with window=0
				var oldCounter = int( getTickCount() / 1000 / 30 ) - 2;
				var oldCode = HOTPGenerate( secret, oldCounter );
				expect( TOTPVerify( secret, oldCode, { window: 0 } ) ).toBeFalse();
			});

		});

	}

}
