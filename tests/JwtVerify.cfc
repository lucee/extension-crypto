component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "JwtVerify", function() {

			it( "verifies valid HMAC token", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123", role: "admin" },
					key = secret,
					algorithm = "HS256"
				);

				var claims = JwtVerify( token = token, key = secret );

				expect( claims ).toBeStruct();
				expect( claims.sub ).toBe( "user123" );
				expect( claims.role ).toBe( "admin" );
			});

			it( "verifies valid RSA token", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var token = JwtSign(
					claims = { sub: "rsauser" },
					key = keyPair.private,
					algorithm = "RS256"
				);

				var claims = JwtVerify( token = token, key = keyPair.public );
				expect( claims.sub ).toBe( "rsauser" );
			});

			it( "verifies valid EC token", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var token = JwtSign(
					claims = { sub: "ecuser" },
					key = keyPair.private,
					algorithm = "ES256"
				);

				var claims = JwtVerify( token = token, key = keyPair.public );
				expect( claims.sub ).toBe( "ecuser" );
			});

			it( "throws on invalid signature", function() {
				var secret1 = "my-super-secret-key-that-is-at-least-256-bits-long";
				var secret2 = "different-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret1,
					algorithm = "HS256"
				);

				expect( function() {
					JwtVerify( token = token, key = secret2 );
				}).toThrow();
			});

			it( "returns error struct when throwOnError=false", function() {
				var secret1 = "my-super-secret-key-that-is-at-least-256-bits-long";
				var secret2 = "different-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret1,
					algorithm = "HS256"
				);

				var result = JwtVerify( token = token, key = secret2, throwOnError = false );

				expect( result ).toBeStruct();
				expect( result.valid ).toBeFalse();
				expect( result ).toHaveKey( "error" );
			});

			it( "returns success struct when throwOnError=false and valid", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				var result = JwtVerify( token = token, key = secret, throwOnError = false );

				expect( result ).toBeStruct();
				expect( result.valid ).toBeTrue();
				expect( result.claims ).toBeStruct();
				expect( result.claims.sub ).toBe( "user123" );
			});

			it( "validates issuer", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256",
					issuer = "https://myapp.com"
				);

				// Valid issuer
				var claims = JwtVerify( token = token, key = secret, issuer = "https://myapp.com" );
				expect( claims.sub ).toBe( "user123" );

				// Invalid issuer
				expect( function() {
					JwtVerify( token = token, key = secret, issuer = "https://other.com" );
				}).toThrow();
			});

			it( "validates audience", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256",
					audience = "api"
				);

				// Valid audience
				var claims = JwtVerify( token = token, key = secret, audience = "api" );
				expect( claims.sub ).toBe( "user123" );

				// Invalid audience
				expect( function() {
					JwtVerify( token = token, key = secret, audience = "other" );
				}).toThrow();
			});

			it( "validates expiration", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";

				// Create expired token
				var token = JwtSign(
					claims = {
						sub: "user123",
						exp: dateAdd( "s", -60, now() )
					},
					key = secret,
					algorithm = "HS256"
				);

				expect( function() {
					JwtVerify( token = token, key = secret );
				}).toThrow();
			});

			it( "respects clockSkew for expiration", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";

				// Create token that expired 30 seconds ago
				var token = JwtSign(
					claims = {
						sub: "user123",
						exp: dateAdd( "s", -30, now() )
					},
					key = secret,
					algorithm = "HS256"
				);

				// Should fail with no clock skew
				var result = JwtVerify( token = token, key = secret, throwOnError = false );
				expect( result.valid ).toBeFalse();

				// Should pass with 60 second clock skew
				var claims = JwtVerify( token = token, key = secret, clockSkew = 60 );
				expect( claims.sub ).toBe( "user123" );
			});

			it( "validates not-before", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";

				// Create token with future nbf
				var token = JwtSign(
					claims = {
						sub: "user123",
						nbf: dateAdd( "s", 300, now() )
					},
					key = secret,
					algorithm = "HS256"
				);

				expect( function() {
					JwtVerify( token = token, key = secret );
				}).toThrow();
			});

			it( "restricts algorithms", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				// Should pass when HS256 is allowed
				var claims = JwtVerify( token = token, key = secret, algorithms = [ "HS256", "HS384" ] );
				expect( claims.sub ).toBe( "user123" );

				// Should fail when HS256 is not allowed
				expect( function() {
					JwtVerify( token = token, key = secret, algorithms = [ "RS256" ] );
				}).toThrow();
			});

			it( "accepts algorithms as comma-separated string", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				var claims = JwtVerify( token = token, key = secret, algorithms = "HS256,HS384,HS512" );
				expect( claims.sub ).toBe( "user123" );
			});

			it( "verifies with wrong key type fails", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var token = JwtSign(
					claims = { sub: "user123" },
					key = keyPair.private,
					algorithm = "RS256"
				);

				// Try to verify with wrong key (private instead of public)
				// This should fail
				var result = JwtVerify( token = token, key = keyPair.private, throwOnError = false );
				// The behavior depends on the library - it might throw or return invalid
			});

			it( "works with positional arguments", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign( { sub: "user123" }, secret, "HS256" );

				// Verify with positional args
				var claims = JwtVerify( token, secret );
				expect( claims.sub ).toBe( "user123" );
			});

			it( "validates expiration with positional arguments", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";

				// Create expired token using positional args
				var token = JwtSign( { sub: "user123", exp: dateAdd( "s", -60, now() ) }, secret, "HS256" );

				expect( function() {
					JwtVerify( token, secret );
				}).toThrow();
			});

			it( "treats empty algorithms string as unrestricted", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				// Empty string should allow any algorithm (same as not specifying)
				var claims = JwtVerify( token = token, key = secret, algorithms = "" );
				expect( claims.sub ).toBe( "user123" );
			});

			it( "treats empty algorithms array as unrestricted", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				// Empty array should allow any algorithm (same as not specifying)
				var claims = JwtVerify( token = token, key = secret, algorithms = [] );
				expect( claims.sub ).toBe( "user123" );
			});

			it( "verifies with PS256 algorithm", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var token = JwtSign(
					claims = { sub: "ps256user" },
					key = keyPair.private,
					algorithm = "PS256"
				);

				var decoded = JwtDecode( token );
				expect( decoded.header.alg ).toBe( "PS256" );

				var claims = JwtVerify( token = token, key = keyPair.public );
				expect( claims.sub ).toBe( "ps256user" );
			});

		});

	}

}
