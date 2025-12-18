component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "JwtDecode", function() {

			it( "decodes JWT header", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				var parts = JwtDecode( token );

				expect( parts ).toBeStruct();
				expect( parts ).toHaveKey( "header" );
				expect( parts.header ).toBeStruct();
				expect( parts.header.alg ).toBe( "HS256" );
			});

			it( "decodes JWT payload", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123", role: "admin", count: 42 },
					key = secret,
					algorithm = "HS256"
				);

				var parts = JwtDecode( token );

				expect( parts ).toHaveKey( "payload" );
				expect( parts.payload ).toBeStruct();
				expect( parts.payload.sub ).toBe( "user123" );
				expect( parts.payload.role ).toBe( "admin" );
				expect( parts.payload.count ).toBe( 42 );
			});

			it( "returns signature", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				var parts = JwtDecode( token );

				expect( parts ).toHaveKey( "signature" );
				expect( parts.signature ).toBeString();
				expect( len( parts.signature ) ).toBeGT( 0 );
			});

			it( "includes kid in header when present", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256",
					kid = "my-key-id"
				);

				var parts = JwtDecode( token );

				expect( parts.header ).toHaveKey( "kid" );
				expect( parts.header.kid ).toBe( "my-key-id" );
			});

			it( "decodes without verifying signature", function() {
				// Create token with one secret
				var secret1 = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret1,
					algorithm = "HS256"
				);

				// Decode should work without any key
				var parts = JwtDecode( token );
				expect( parts.payload.sub ).toBe( "user123" );
			});

			it( "decodes RSA signed token", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var token = JwtSign(
					claims = { sub: "rsauser", admin: true },
					key = keyPair.private,
					algorithm = "RS256"
				);

				var parts = JwtDecode( token );

				expect( parts.header.alg ).toBe( "RS256" );
				expect( parts.payload.sub ).toBe( "rsauser" );
				expect( parts.payload.admin ).toBeTrue();
			});

			it( "decodes EC signed token", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var token = JwtSign(
					claims = { sub: "ecuser" },
					key = keyPair.private,
					algorithm = "ES256"
				);

				var parts = JwtDecode( token );

				expect( parts.header.alg ).toBe( "ES256" );
				expect( parts.payload.sub ).toBe( "ecuser" );
			});

			it( "decodes token with all standard claims", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var nowTime = now();
				var expTime = dateAdd( "h", 1, nowTime );

				var token = JwtSign(
					claims = {
						sub: "user123",
						iss: "https://issuer.com",
						aud: "api",
						exp: expTime,
						iat: nowTime,
						nbf: nowTime,
						jti: "unique-id-123"
					},
					key = secret,
					algorithm = "HS256"
				);

				var parts = JwtDecode( token );

				expect( parts.payload.sub ).toBe( "user123" );
				expect( parts.payload.iss ).toBe( "https://issuer.com" );
				// aud is always an array per JWT spec
				expect( parts.payload.aud ).toBeArray();
				expect( parts.payload.aud ).toInclude( "api" );
				expect( parts.payload ).toHaveKey( "exp" );
				expect( parts.payload ).toHaveKey( "iat" );
				expect( parts.payload ).toHaveKey( "nbf" );
				expect( parts.payload.jti ).toBe( "unique-id-123" );
			});

			it( "throws on invalid token format", function() {
				expect( function() {
					JwtDecode( "not-a-valid-jwt" );
				}).toThrow();
			});

			it( "throws on empty token", function() {
				expect( function() {
					JwtDecode( "" );
				}).toThrow();
			});

		});

	}

}
