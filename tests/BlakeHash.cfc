component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateBlake2bHash", function() {

			it( "generates a 256-bit hash by default", function() {
				var hash = GenerateBlake2bHash( "hello world" );

				expect( hash ).toBeString();
				expect( len( hash ) ).toBe( 64 );  // 32 bytes = 64 hex chars
			});

			it( "generates consistent hashes", function() {
				var hash1 = GenerateBlake2bHash( "test data" );
				var hash2 = GenerateBlake2bHash( "test data" );

				expect( hash1 ).toBe( hash2 );
			});

			it( "generates different hashes for different input", function() {
				var hash1 = GenerateBlake2bHash( "test1" );
				var hash2 = GenerateBlake2bHash( "test2" );

				expect( hash1 ).notToBe( hash2 );
			});

			it( "supports custom output length", function() {
				var hash16 = GenerateBlake2bHash( "test", 16 );
				var hash64 = GenerateBlake2bHash( "test", 64 );

				expect( len( hash16 ) ).toBe( 32 );  // 16 bytes = 32 hex chars
				expect( len( hash64 ) ).toBe( 128 ); // 64 bytes = 128 hex chars
			});

			it( "supports keyed mode", function() {
				var key = "mysecretkey12345678901234567890ab";  // 32 bytes
				var hash1 = GenerateBlake2bHash( "data", 32, key );
				var hash2 = GenerateBlake2bHash( "data", 32, "differentkey123456789012345678901" );

				expect( hash1 ).notToBe( hash2 );
			});

			it( "accepts binary input", function() {
				var binary = charsetDecode( "hello", "utf-8" );
				var hash = GenerateBlake2bHash( binary );

				expect( hash ).toBeString();
				expect( len( hash ) ).toBe( 64 );
			});

		});

		describe( "GenerateBlake2sHash", function() {

			it( "generates a 256-bit hash by default", function() {
				var hash = GenerateBlake2sHash( "hello world" );

				expect( hash ).toBeString();
				expect( len( hash ) ).toBe( 64 );  // 32 bytes = 64 hex chars
			});

			it( "generates consistent hashes", function() {
				var hash1 = GenerateBlake2sHash( "test data" );
				var hash2 = GenerateBlake2sHash( "test data" );

				expect( hash1 ).toBe( hash2 );
			});

			it( "supports custom output length up to 32 bytes", function() {
				var hash16 = GenerateBlake2sHash( "test", 16 );
				var hash32 = GenerateBlake2sHash( "test", 32 );

				expect( len( hash16 ) ).toBe( 32 );  // 16 bytes = 32 hex chars
				expect( len( hash32 ) ).toBe( 64 );  // 32 bytes = 64 hex chars
			});

			it( "supports keyed mode", function() {
				var key = "mysecretkey123456789012345678901";  // 31 bytes (under limit)
				var hash1 = GenerateBlake2sHash( "data", 32, key );
				var hash2 = GenerateBlake2sHash( "data", 32, "differentkey1234567890123456789" );

				expect( hash1 ).notToBe( hash2 );
			});

		});

		describe( "GenerateBlake3Hash", function() {

			it( "generates a 256-bit hash by default", function() {
				var hash = GenerateBlake3Hash( "hello world" );

				expect( hash ).toBeString();
				expect( len( hash ) ).toBe( 64 );  // 32 bytes = 64 hex chars
			});

			it( "generates consistent hashes", function() {
				var hash1 = GenerateBlake3Hash( "test data" );
				var hash2 = GenerateBlake3Hash( "test data" );

				expect( hash1 ).toBe( hash2 );
			});

			it( "supports arbitrary output length (XOF)", function() {
				var hash16 = GenerateBlake3Hash( "test", 16 );
				var hash128 = GenerateBlake3Hash( "test", 128 );

				expect( len( hash16 ) ).toBe( 32 );   // 16 bytes = 32 hex chars
				expect( len( hash128 ) ).toBe( 256 ); // 128 bytes = 256 hex chars
			});

			it( "supports keyed mode with 32-byte key", function() {
				var key = "12345678901234567890123456789012";  // exactly 32 bytes
				var hash1 = GenerateBlake3Hash( "data", 32, key );
				var hash2 = GenerateBlake3Hash( "data", 32, "abcdefghijklmnopqrstuvwxyz012345" );

				expect( hash1 ).notToBe( hash2 );
			});

			it( "supports key derivation mode with context", function() {
				var hash1 = GenerateBlake3Hash( "secret", 32, "", "MyApp v1 encryption" );
				var hash2 = GenerateBlake3Hash( "secret", 32, "", "MyApp v1 authentication" );

				expect( hash1 ).notToBe( hash2 );
			});

			it( "accepts binary input", function() {
				var binary = charsetDecode( "hello", "utf-8" );
				var hash = GenerateBlake3Hash( binary );

				expect( hash ).toBeString();
				expect( len( hash ) ).toBe( 64 );
			});

		});

		describe( "Blake hash comparison", function() {

			it( "Blake2b, Blake2s, and Blake3 produce different hashes", function() {
				var input = "same input";
				var blake2b = GenerateBlake2bHash( input );
				var blake2s = GenerateBlake2sHash( input );
				var blake3 = GenerateBlake3Hash( input );

				expect( blake2b ).notToBe( blake2s );
				expect( blake2b ).notToBe( blake3 );
				expect( blake2s ).notToBe( blake3 );
			});

		});

	}

}
