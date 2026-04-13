component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "CborEncode / CborDecode roundtrip", function() {

			it( "roundtrips a simple struct", function() {
				var data = { name: "Zac", age: 42 };
				var encoded = CborEncode( data );

				expect( isBinary( encoded ) ).toBeTrue();

				var decoded = CborDecode( encoded );
				expect( decoded.name ).toBe( "Zac" );
				expect( decoded.age ).toBe( 42 );
			});

			it( "roundtrips an array", function() {
				var data = [ 1, 2, 3, "four", true ];
				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded );

				expect( decoded ).toBeArray();
				expect( arrayLen( decoded ) ).toBe( 5 );
				expect( decoded[ 1 ] ).toBe( 1 );
				expect( decoded[ 4 ] ).toBe( "four" );
				expect( decoded[ 5 ] ).toBeTrue();
			});

			it( "roundtrips a string", function() {
				var encoded = CborEncode( "hello world" );
				var decoded = CborDecode( encoded );

				expect( decoded ).toBe( "hello world" );
			});

			it( "roundtrips an integer", function() {
				var encoded = CborEncode( 12345 );
				var decoded = CborDecode( encoded );

				expect( decoded ).toBe( 12345 );
			});

			it( "roundtrips a negative integer", function() {
				var encoded = CborEncode( -99 );
				var decoded = CborDecode( encoded );

				expect( decoded ).toBe( -99 );
			});

			it( "roundtrips a float", function() {
				var encoded = CborEncode( 3.14 );
				var decoded = CborDecode( encoded );

				expect( decoded ).toBeCloseTo( 3.14, 2 );
			});

			it( "roundtrips a boolean", function() {
				var encoded = CborEncode( true );
				var decoded = CborDecode( encoded );

				expect( decoded ).toBeTrue();
			});

			it( "roundtrips binary data", function() {
				var data = charsetDecode( "binary payload", "UTF-8" );
				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded );

				expect( isBinary( decoded ) ).toBeTrue();
				expect( charsetEncode( decoded, "UTF-8" ) ).toBe( "binary payload" );
			});

			it( "roundtrips nested structs and arrays", function() {
				var data = {
					users: [
						{ name: "Alice", scores: [ 10, 20, 30 ] },
						{ name: "Bob", scores: [ 40, 50 ] }
					],
					count: 2
				};
				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded );

				expect( decoded.count ).toBe( 2 );
				expect( arrayLen( decoded.users ) ).toBe( 2 );
				expect( decoded.users[ 1 ].name ).toBe( "Alice" );
				expect( decoded.users[ 1 ].scores[ 3 ] ).toBe( 30 );
				expect( decoded.users[ 2 ].name ).toBe( "Bob" );
			});

			it( "roundtrips an empty struct", function() {
				var encoded = CborEncode( {} );
				var decoded = CborDecode( encoded );

				expect( isStruct( decoded ) ).toBeTrue();
				expect( structCount( decoded ) ).toBe( 0 );
			});

			it( "roundtrips an empty array", function() {
				var encoded = CborEncode( [] );
				var decoded = CborDecode( encoded );

				expect( isArray( decoded ) ).toBeTrue();
				expect( arrayLen( decoded ) ).toBe( 0 );
			});

		});

		describe( "CborDecode options", function() {

			it( "preserves tags by default", function() {
				// CBOR tag 1 = epoch timestamp. Encode manually via JsonToCbor won't have tags,
				// but we can test the option struct is accepted without error
				var data = { key: "value" };
				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded, { preserveTags: true } );

				expect( decoded.key ).toBe( "value" );
			});

			it( "accepts preserveTags=false", function() {
				var data = { key: "value" };
				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded, { preserveTags: false } );

				expect( decoded.key ).toBe( "value" );
			});

		});

		describe( "CborToJson", function() {

			it( "converts CBOR struct to JSON", function() {
				var data = { name: "test", value: 42 };
				var cbor = CborEncode( data );
				var json = CborToJson( cbor );

				expect( isJSON( json ) ).toBeTrue();
				var parsed = deserializeJSON( json );
				expect( parsed.name ).toBe( "test" );
				expect( parsed.value ).toBe( 42 );
			});

			it( "converts CBOR array to JSON", function() {
				var data = [ 1, "two", 3 ];
				var cbor = CborEncode( data );
				var json = CborToJson( cbor );

				expect( isJSON( json ) ).toBeTrue();
				var parsed = deserializeJSON( json );
				expect( arrayLen( parsed ) ).toBe( 3 );
			});

		});

		describe( "JsonToCbor", function() {

			it( "converts JSON to CBOR and back", function() {
				var json = '{"name":"test","value":42}';
				var cbor = JsonToCbor( json );

				expect( isBinary( cbor ) ).toBeTrue();

				// Verify by converting back
				var backToJson = CborToJson( cbor );
				var parsed = deserializeJSON( backToJson );
				expect( parsed.name ).toBe( "test" );
				expect( parsed.value ).toBe( 42 );
			});

			it( "roundtrips JSON array", function() {
				var json = '[1,2,3,"four"]';
				var cbor = JsonToCbor( json );
				var backToJson = CborToJson( cbor );
				var parsed = deserializeJSON( backToJson );

				expect( arrayLen( parsed ) ).toBe( 4 );
				expect( parsed[ 4 ] ).toBe( "four" );
			});

		});

		describe( "CborEncode with integer keys", function() {

			it( "preserves numeric struct keys for COSE compatibility", function() {
				// COSE keys use integer keys like 1, 3, -1, -2, -3
				var data = {};
				data[ "1" ] = 2;
				data[ "3" ] = -7;
				data[ "-1" ] = 1;

				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded );

				expect( decoded[ "1" ] ).toBe( 2 );
				expect( decoded[ "3" ] ).toBe( -7 );
				expect( decoded[ "-1" ] ).toBe( 1 );
			});

		});

		describe( "known limitations: CFML struct keys are always strings", function() {

			it( "CBOR text key '1' roundtrips as integer key 1", function() {
				// CBOR allows text key "1" (string) and integer key 1 as distinct entries.
				// CFML struct keys are always strings, so CborEncode sees "1" and
				// encodes it as CBOR integer 1 — the original text key is lost.
				// This is fine for COSE/WebAuthn (integer keys only) but lossy for
				// general CBOR maps that use text-numeric keys.
				var json = '{"1":"from text key"}';
				var cbor = JsonToCbor( json );
				var decoded = CborDecode( cbor );

				// Text key "1" from JSON decoded to struct key "1" — so far so good
				expect( decoded[ "1" ] ).toBe( "from text key" );

				// Re-encode: struct key "1" becomes CBOR integer key 1, not text key "1"
				var reEncoded = CborEncode( decoded );
				var reJson = CborToJson( reEncoded );

				// The JSON output now has integer key "1", not text key — data was preserved
				// but the CBOR key type changed from text to integer
				expect( isJSON( reJson ) ).toBeTrue();
			});

			it( "leading zeros in keys are not preserved", function() {
				// Struct key "01" parses as integer 1, so roundtrip mangles the key
				var data = {};
				data[ "01" ] = "leading zero";

				var encoded = CborEncode( data );
				var decoded = CborDecode( encoded );

				// CFML may or may not preserve "01" vs "1" as a struct key depending
				// on implementation, but the CBOR integer key will be 1
				var json = CborToJson( encoded );
				// The key in CBOR is integer 1, which serializes as "1" in JSON
				expect( json ).toInclude( """1""" );
			});

		});

	}

}
