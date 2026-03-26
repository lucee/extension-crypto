/**
 * Tests for HOTP functions: HOTPGenerate(), HOTPVerify().
 *
 * HOTP (HMAC-based One-Time Password, RFC 4226) is the counter-based
 * variant. TOTP builds on top of it.
 *
 * RFC 4226 Appendix D provides test vectors for the secret "12345678901234567890"
 * (ASCII) with SHA1.
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	// RFC 4226 test secret: ASCII "12345678901234567890" = Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	variables.rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

	// RFC 4226 Appendix D expected HOTP values for counters 0-9
	variables.rfcExpected = [
		"755224",
		"287082",
		"359152",
		"969429",
		"338314",
		"254676",
		"287922",
		"162583",
		"399871",
		"520489"
	];

	function run( testResults, testBox ) {

		describe( "HOTPGenerate RFC 4226 test vectors", function() {

			it( "produces correct codes for counters 0-9", function() {
				for ( var i = 1; i <= arrayLen( variables.rfcExpected ); i++ ) {
					var code = HOTPGenerate( variables.rfcSecret, i - 1 );
					expect( code ).toBe( variables.rfcExpected[ i ],
						"Counter #i - 1#: expected #variables.rfcExpected[ i ]# got #code#" );
				}
			});

		});

		describe( "HOTPGenerate", function() {

			it( "returns a 6-digit string by default", function() {
				var code = HOTPGenerate( variables.rfcSecret, 0 );

				expect( len( code ) ).toBe( 6 );
				expect( code ).toMatch( "^\d{6}$" );
			});

			it( "supports 8-digit codes", function() {
				var code = HOTPGenerate( variables.rfcSecret, 0, { digits: 8 } );

				expect( len( code ) ).toBe( 8 );
				expect( code ).toMatch( "^\d{8}$" );
			});

			it( "supports SHA256 algorithm", function() {
				var code = HOTPGenerate( variables.rfcSecret, 0, { algorithm: "SHA256" } );

				expect( len( code ) ).toBe( 6 );
				expect( code ).toMatch( "^\d{6}$" );
			});

			it( "supports SHA512 algorithm", function() {
				var code = HOTPGenerate( variables.rfcSecret, 0, { algorithm: "SHA512" } );

				expect( len( code ) ).toBe( 6 );
				expect( code ).toMatch( "^\d{6}$" );
			});

			it( "different counters produce different codes", function() {
				var code1 = HOTPGenerate( variables.rfcSecret, 0 );
				var code2 = HOTPGenerate( variables.rfcSecret, 1 );

				expect( code1 ).notToBe( code2 );
			});

			it( "same counter always produces the same code (deterministic)", function() {
				var code1 = HOTPGenerate( variables.rfcSecret, 42 );
				var code2 = HOTPGenerate( variables.rfcSecret, 42 );

				expect( code1 ).toBe( code2 );
			});

		});

		describe( "HOTPVerify", function() {

			it( "verifies correct code at exact counter", function() {
				var code = HOTPGenerate( variables.rfcSecret, 5 );
				var result = HOTPVerify( variables.rfcSecret, code, 5 );

				expect( result ).toBeTrue();
			});

			it( "rejects incorrect code", function() {
				var result = HOTPVerify( variables.rfcSecret, "000000", 0 );

				expect( result ).toBeFalse();
			});

			it( "rejects correct code at wrong counter", function() {
				var code = HOTPGenerate( variables.rfcSecret, 5 );
				var result = HOTPVerify( variables.rfcSecret, code, 6 );

				expect( result ).toBeFalse();
			});

			it( "supports window for counter desync", function() {
				// Code generated at counter 5
				var code = HOTPGenerate( variables.rfcSecret, 5 );

				// Should fail at counter 3 with default window=0
				expect( HOTPVerify( variables.rfcSecret, code, 3 ) ).toBeFalse();

				// Should pass at counter 3 with window=5 (checks 3 through 8)
				expect( HOTPVerify( variables.rfcSecret, code, 3, { window: 5 } ) ).toBeTrue();
			});

			it( "verifies RFC 4226 test vectors", function() {
				for ( var i = 1; i <= arrayLen( variables.rfcExpected ); i++ ) {
					expect( HOTPVerify( variables.rfcSecret, variables.rfcExpected[ i ], i - 1 ) ).toBeTrue(
						"Counter #i - 1# should verify" );
				}
			});

		});

	}

}
