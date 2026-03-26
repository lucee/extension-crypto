/**
 * Tests for JWK functions: KeyToJwk(), JwkToKey(), JwksLoad().
 *
 * JWK (JSON Web Key, RFC 7517) support completes the JWT workflow:
 * fetch a provider's JWKS, extract the right key by kid, verify the token.
 * Built on Nimbus JOSE+JWT which is already a dependency for JWT support.
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "KeyToJwk with RSA keys", function() {

			it( "converts an RSA key pair struct to JWK", function() {
				var kp = GenerateKeyPair( "RSA" );
				var jwk = KeyToJwk( kp );

				expect( jwk ).toBeStruct();
				expect( jwk.kty ).toBe( "RSA" );
				// Should have public components
				expect( jwk ).toHaveKey( "n" );
				expect( jwk ).toHaveKey( "e" );
				// Should have private component (d) since we passed the full key pair
				expect( jwk ).toHaveKey( "d" );
			});

			it( "converts an RSA public PEM to JWK (no private material)", function() {
				var kp = GenerateKeyPair( "RSA" );
				var jwk = KeyToJwk( kp.public );

				expect( jwk.kty ).toBe( "RSA" );
				expect( jwk ).toHaveKey( "n" );
				expect( jwk ).toHaveKey( "e" );
				expect( jwk ).notToHaveKey( "d" );
			});

		});

		describe( "KeyToJwk with EC keys", function() {

			it( "converts a P-256 key pair to JWK", function() {
				var kp = GenerateKeyPair( "EC" );
				var jwk = KeyToJwk( kp );

				expect( jwk.kty ).toBe( "EC" );
				expect( jwk.crv ).toBe( "P-256" );
				expect( jwk ).toHaveKey( "x" );
				expect( jwk ).toHaveKey( "y" );
				expect( jwk ).toHaveKey( "d" );
			});

			it( "converts a P-384 key pair to JWK", function() {
				var kp = GenerateKeyPair( "P-384" );
				var jwk = KeyToJwk( kp );

				expect( jwk.crv ).toBe( "P-384" );
			});

			it( "converts a P-521 key pair to JWK", function() {
				var kp = GenerateKeyPair( "P-521" );
				var jwk = KeyToJwk( kp );

				expect( jwk.crv ).toBe( "P-521" );
			});

		});

		describe( "KeyToJwk with Ed25519 keys", function() {

			it( "converts an Ed25519 key pair to JWK", function() {
				var kp = GenerateKeyPair( "Ed25519" );
				var jwk = KeyToJwk( kp );

				expect( jwk.kty ).toBe( "OKP" );
				expect( jwk.crv ).toBe( "Ed25519" );
				expect( jwk ).toHaveKey( "x" );
				expect( jwk ).toHaveKey( "d" );
			});

		});

		describe( "JwkToKey", function() {

			it( "round-trips an RSA key pair through JWK (private key)", function() {
				var kp = GenerateKeyPair( "RSA" );
				var jwk = KeyToJwk( kp );

				// Convert back — JWK has private key material so we get a PrivateKey
				var key = JwkToKey( jwk );
				expect( key.getClass().getName() ).toInclude( "RSA" );
				expect( key.getClass().getName() ).toInclude( "Private" );
			});

			it( "converts a public-only RSA JWK to PublicKey and verifies JWT", function() {
				var kp = GenerateKeyPair( "RSA" );
				var jwk = KeyToJwk( kp.public );

				var pubKey = JwkToKey( jwk );

				// Sign with original private key, verify with round-tripped public key
				var jwt = JwtSign( { "sub": "test" }, kp.private );
				var claims = JwtVerify( jwt, pubKey );

				expect( claims.sub ).toBe( "test" );
			});

			it( "converts a public-only EC JWK to PublicKey and verifies JWT", function() {
				var kp = GenerateKeyPair( "EC" );
				var jwk = KeyToJwk( kp.public );

				var pubKey = JwkToKey( jwk );

				var jwt = JwtSign( { "sub": "test" }, kp.private );
				var claims = JwtVerify( jwt, pubKey );

				expect( claims.sub ).toBe( "test" );
			});

			it( "converts an Ed25519 JWK back to a key and verifies JWT", function() {
				var kp = GenerateKeyPair( "Ed25519" );
				var jwk = KeyToJwk( kp.public );

				var pubKey = JwkToKey( jwk );

				var jwt = JwtSign( { "sub": "test" }, kp.private );
				var claims = JwtVerify( jwt, pubKey );

				expect( claims.sub ).toBe( "test" );
			});

			it( "accepts a JSON string", function() {
				var kp = GenerateKeyPair( "RSA" );
				var jwk = KeyToJwk( kp.public );

				// Convert struct to JSON string
				var json = serializeJSON( jwk );
				var pubKey = JwkToKey( json );

				var jwt = JwtSign( { "sub": "test" }, kp.private );
				var claims = JwtVerify( jwt, pubKey );

				expect( claims.sub ).toBe( "test" );
			});

		});

		describe( "JwksLoad", function() {

			it( "parses a JWKS JSON string", function() {
				// Build a JWKS from a generated key
				var kp = GenerateKeyPair( "RSA" );
				var jwk = KeyToJwk( kp.public );

				var jwksJson = '{"keys":[' & serializeJSON( jwk ) & ']}';
				var keys = JwksLoad( jwksJson );

				expect( keys ).toBeArray();
				expect( arrayLen( keys ) ).toBe( 1 );
				expect( keys[ 1 ].kty ).toBe( "RSA" );
			});

			it( "parses a JWKS with multiple keys", function() {
				var rsaKp = GenerateKeyPair( "RSA" );
				var ecKp = GenerateKeyPair( "EC" );

				var rsaJwk = serializeJSON( KeyToJwk( rsaKp.public ) );
				var ecJwk = serializeJSON( KeyToJwk( ecKp.public ) );

				var jwksJson = '{"keys":[' & rsaJwk & ',' & ecJwk & ']}';
				var keys = JwksLoad( jwksJson );

				expect( arrayLen( keys ) ).toBe( 2 );
			});

			it( "full JWT verification workflow with JWKS", function() {
				// Simulate: provider publishes JWKS, consumer fetches it and verifies a JWT
				var kp = GenerateKeyPair( "RSA" );

				// Provider signs a JWT
				var jwt = JwtSign( { "sub": "user123", "iss": "provider" }, kp.private );

				// Provider publishes their public key as JWKS
				var jwksJson = '{"keys":[' & serializeJSON( KeyToJwk( kp.public ) ) & ']}';

				// Consumer loads JWKS and verifies
				var keys = JwksLoad( jwksJson );
				var pubKey = JwkToKey( keys[ 1 ] );
				var claims = JwtVerify( jwt, pubKey );

				expect( claims.sub ).toBe( "user123" );
			});

		});

	}

}
