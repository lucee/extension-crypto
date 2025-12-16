component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateHKDFKey", function() {

			it( "derives key material with SHA256", function() {
				var ikm = "secret input key material";
				var salt = "random salt value";
				var info = "application context";

				var key = GenerateHKDFKey( "SHA256", ikm, salt, info, 32 );

				expect( isBinary( key ) ).toBeTrue();
				expect( len( key ) ).toBe( 32 );
			});

			it( "produces consistent results", function() {
				var key1 = GenerateHKDFKey( "SHA256", "secret", "salt", "info", 32 );
				var key2 = GenerateHKDFKey( "SHA256", "secret", "salt", "info", 32 );

				expect( binaryEncode( key1, "hex" ) ).toBe( binaryEncode( key2, "hex" ) );
			});

			it( "produces different keys for different info", function() {
				var key1 = GenerateHKDFKey( "SHA256", "secret", "salt", "encryption", 32 );
				var key2 = GenerateHKDFKey( "SHA256", "secret", "salt", "authentication", 32 );

				expect( binaryEncode( key1, "hex" ) ).notToBe( binaryEncode( key2, "hex" ) );
			});

			it( "supports SHA384", function() {
				var key = GenerateHKDFKey( "SHA384", "secret", "salt", "info", 48 );

				expect( isBinary( key ) ).toBeTrue();
				expect( len( key ) ).toBe( 48 );
			});

			it( "supports SHA512", function() {
				var key = GenerateHKDFKey( "SHA512", "secret", "salt", "info", 64 );

				expect( isBinary( key ) ).toBeTrue();
				expect( len( key ) ).toBe( 64 );
			});

			it( "works with empty salt", function() {
				var key = GenerateHKDFKey( "SHA256", "secret", "", "info", 32 );

				expect( isBinary( key ) ).toBeTrue();
				expect( len( key ) ).toBe( 32 );
			});

			it( "works with empty info", function() {
				var key = GenerateHKDFKey( "SHA256", "secret", "salt", "", 32 );

				expect( isBinary( key ) ).toBeTrue();
				expect( len( key ) ).toBe( 32 );
			});

			it( "accepts binary input", function() {
				var ikm = charsetDecode( "secret", "utf-8" );
				var salt = charsetDecode( "salt", "utf-8" );
				var info = charsetDecode( "info", "utf-8" );

				var key = GenerateHKDFKey( "SHA256", ikm, salt, info, 32 );

				expect( isBinary( key ) ).toBeTrue();
			});

		});

		describe( "HKDFExtract and HKDFExpand", function() {

			it( "extract creates PRK of correct size", function() {
				var prk = HKDFExtract( "SHA256", "salt", "secret" );

				expect( isBinary( prk ) ).toBeTrue();
				expect( len( prk ) ).toBe( 32 );  // SHA256 output size
			});

			it( "expand derives key from PRK", function() {
				var prk = HKDFExtract( "SHA256", "salt", "secret" );
				var key = HKDFExpand( "SHA256", prk, "context", 32 );

				expect( isBinary( key ) ).toBeTrue();
				expect( len( key ) ).toBe( 32 );
			});

			it( "derives same key as one-shot function", function() {
				// One-shot approach
				var keyOneShot = GenerateHKDFKey( "SHA256", "secret", "salt", "info", 32 );

				// Two-phase approach
				var prk = HKDFExtract( "SHA256", "salt", "secret" );
				var keyTwoPhase = HKDFExpand( "SHA256", prk, "info", 32 );

				expect( binaryEncode( keyOneShot, "hex" ) ).toBe( binaryEncode( keyTwoPhase, "hex" ) );
			});

			it( "can derive multiple keys from same PRK", function() {
				var prk = HKDFExtract( "SHA256", "salt", "master secret" );

				var encKey = HKDFExpand( "SHA256", prk, "encryption key", 32 );
				var authKey = HKDFExpand( "SHA256", prk, "authentication key", 32 );
				var ivKey = HKDFExpand( "SHA256", prk, "iv", 16 );

				// All should be different
				expect( binaryEncode( encKey, "hex" ) ).notToBe( binaryEncode( authKey, "hex" ) );
				expect( binaryEncode( encKey, "hex" ) ).notToBe( binaryEncode( ivKey, "hex" ) );
				expect( binaryEncode( authKey, "hex" ) ).notToBe( binaryEncode( ivKey, "hex" ) );

				// Sizes should be correct
				expect( len( encKey ) ).toBe( 32 );
				expect( len( authKey ) ).toBe( 32 );
				expect( len( ivKey ) ).toBe( 16 );
			});

			it( "SHA384 produces 48-byte PRK", function() {
				var prk = HKDFExtract( "SHA384", "salt", "secret" );

				expect( len( prk ) ).toBe( 48 );
			});

			it( "SHA512 produces 64-byte PRK", function() {
				var prk = HKDFExtract( "SHA512", "salt", "secret" );

				expect( len( prk ) ).toBe( 64 );
			});

		});

	}

}
