component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "Base64UrlEncode", function() {

			it( "encodes string data", function() {
				var encoded = Base64UrlEncode( "Hello World" );

				expect( encoded ).toBe( "SGVsbG8gV29ybGQ" );
				// No padding
				expect( encoded ).notToInclude( "=" );
			});

			it( "encodes binary data", function() {
				var binary = charsetDecode( "test", "UTF-8" );
				var encoded = Base64UrlEncode( binary );

				expect( encoded ).toBe( "dGVzdA" );
			});

			it( "produces URL-safe output", function() {
				// Data that would produce + and / in standard Base64
				var data = charsetDecode( ">>???", "UTF-8" );
				var encoded = Base64UrlEncode( data );

				expect( encoded ).notToInclude( "+" );
				expect( encoded ).notToInclude( "/" );
			});

		});

		describe( "Base64UrlDecode", function() {

			it( "decodes to binary by default", function() {
				var decoded = Base64UrlDecode( "SGVsbG8gV29ybGQ" );

				expect( isBinary( decoded ) ).toBeTrue();
				expect( charsetEncode( decoded, "UTF-8" ) ).toBe( "Hello World" );
			});

			it( "decodes to string with charset", function() {
				var decoded = Base64UrlDecode( "SGVsbG8gV29ybGQ", "UTF-8" );

				expect( isSimpleValue( decoded ) ).toBeTrue();
				expect( decoded ).toBe( "Hello World" );
			});

			it( "handles missing padding", function() {
				// Base64URL typically omits padding
				var decoded = Base64UrlDecode( "dGVzdA", "UTF-8" );
				expect( decoded ).toBe( "test" );
			});

		});

		describe( "roundtrip", function() {

			it( "encodes and decodes correctly", function() {
				var original = "The quick brown fox jumps over the lazy dog!";
				var encoded = Base64UrlEncode( original );
				var decoded = Base64UrlDecode( encoded, "UTF-8" );

				expect( decoded ).toBe( original );
			});

		});

	}

}
