component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "JwtSign", function() {

			it( "signs with HMAC secret string", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123", role: "admin" },
					key = secret,
					algorithm = "HS256"
				);

				expect( token ).toBeString();
				expect( token ).toMatch( "^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" );

				// Verify the token
				var claims = JwtVerify( token = token, key = secret );
				expect( claims.sub ).toBe( "user123" );
				expect( claims.role ).toBe( "admin" );
			});

			it( "signs with HS384 algorithm", function() {
				var secret = "my-super-secret-key-that-is-at-least-384-bits-long-for-hs384";
				var token = JwtSign(
					claims = { sub: "user456" },
					key = secret,
					algorithm = "HS384"
				);

				var decoded = JwtDecode( token );
				expect( decoded.header.alg ).toBe( "HS384" );
			});

			it( "signs with HS512 algorithm", function() {
				var secret = "my-super-secret-key-that-is-at-least-512-bits-long-for-hs512-algorithm-testing";
				var token = JwtSign(
					claims = { sub: "user789" },
					key = secret,
					algorithm = "HS512"
				);

				var decoded = JwtDecode( token );
				expect( decoded.header.alg ).toBe( "HS512" );
			});

			it( "signs with RSA private key", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var token = JwtSign(
					claims = { sub: "user123", admin: true },
					key = keyPair.private,
					algorithm = "RS256"
				);

				expect( token ).toBeString();

				// Verify with public key
				var claims = JwtVerify( token = token, key = keyPair.public );
				expect( claims.sub ).toBe( "user123" );
				expect( claims.admin ).toBeTrue();
			});

			it( "signs with EC private key (P-256)", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var token = JwtSign(
					claims = { sub: "ecuser" },
					key = keyPair.private,
					algorithm = "ES256"
				);

				var decoded = JwtDecode( token );
				expect( decoded.header.alg ).toBe( "ES256" );

				var claims = JwtVerify( token = token, key = keyPair.public );
				expect( claims.sub ).toBe( "ecuser" );
			});

			it( "auto-detects algorithm from key type", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var token = JwtSign(
					claims = { sub: "autodetect" },
					key = keyPair.private
				);

				var decoded = JwtDecode( token );
				// Should auto-detect RS256 for RSA keys
				expect( decoded.header.alg ).toBe( "RS256" );
			});

			it( "sets expiresIn correctly", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256",
					expiresIn = 3600
				);

				var decoded = JwtDecode( token );
				expect( decoded.payload ).toHaveKey( "exp" );

				var expTime = decoded.payload.exp;
				// exp should be roughly 1 hour from now (with some tolerance)
				expect( expTime ).toBeDate();
				expect( dateDiff( "n", now(), expTime ) ).toBeGTE( 55 );
				expect( dateDiff( "n", now(), expTime ) ).toBeLTE( 65 );
			});

			it( "sets issuer and audience", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256",
					issuer = "https://myapp.com",
					audience = "api"
				);

				var decoded = JwtDecode( token );
				expect( decoded.payload.iss ).toBe( "https://myapp.com" );
				// aud is always an array per JWT spec
				expect( decoded.payload.aud ).toBeArray();
				expect( decoded.payload.aud ).toInclude( "api" );
			});

			it( "sets kid in header", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256",
					kid = "key-2024-01"
				);

				var decoded = JwtDecode( token );
				expect( decoded.header.kid ).toBe( "key-2024-01" );
			});

			it( "auto-sets iat claim", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = { sub: "user123" },
					key = secret,
					algorithm = "HS256"
				);

				var decoded = JwtDecode( token );
				expect( decoded.payload ).toHaveKey( "iat" );

				var iatTime = decoded.payload.iat;
				// iat should be close to now
				expect( iatTime ).toBeDate();
				expect( abs( dateDiff( "s", now(), iatTime ) ) ).toBeLTE( 5 );
			});

			it( "preserves custom claims", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var token = JwtSign(
					claims = {
						sub: "user123",
						customString: "hello",
						customNumber: 42,
						customBool: true,
						customArray: [ "a", "b", "c" ]
					},
					key = secret,
					algorithm = "HS256"
				);

				var claims = JwtVerify( token = token, key = secret );
				expect( claims.customString ).toBe( "hello" );
				expect( claims.customNumber ).toBe( 42 );
				expect( claims.customBool ).toBeTrue();
				expect( claims.customArray ).toBeArray();
				expect( claims.customArray ).toHaveLength( 3 );
			});

			it( "works with positional arguments", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";

				// Positional: claims, key, algorithm
				var token = JwtSign( { sub: "positional-user" }, secret, "HS256" );

				expect( token ).toBeString();
				expect( token ).toMatch( "^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" );

				var claims = JwtVerify( token, secret );
				expect( claims.sub ).toBe( "positional-user" );
			});

			it( "preserves exp claim with named arguments", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var expTime = dateAdd( "h", 1, now() );

				// Named args with explicit exp in claims
				var token = JwtSign(
					claims = { sub: "user123", exp: expTime },
					key = secret,
					algorithm = "HS256"
				);

				var decoded = JwtDecode( token );
				// exp should be close to what we passed (within 5 seconds tolerance)
				expect( abs( dateDiff( "s", expTime, decoded.payload.exp ) ) ).toBeLTE( 5 );
			});

			it( "preserves exp claim with positional arguments", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var expTime = dateAdd( "h", 1, now() );

				// Positional args with explicit exp in claims
				var token = JwtSign( { sub: "user123", exp: expTime }, secret, "HS256" );

				var decoded = JwtDecode( token );
				// exp should be close to what we passed (within 5 seconds tolerance)
				expect( abs( dateDiff( "s", expTime, decoded.payload.exp ) ) ).toBeLTE( 5 );
			});

			it( "explicit exp in claims takes precedence over expiresIn param", function() {
				var secret = "my-super-secret-key-that-is-at-least-256-bits-long";
				var explicitExp = dateAdd( "h", 2, now() ); // 2 hours from now

				// Pass both exp in claims AND expiresIn param - exp should win
				var token = JwtSign(
					claims = { sub: "user123", exp: explicitExp },
					key = secret,
					algorithm = "HS256",
					expiresIn = 3600 // 1 hour - should be ignored
				);

				var decoded = JwtDecode( token );
				// exp should be ~2 hours from now (the explicit value), not 1 hour
				expect( dateDiff( "n", now(), decoded.payload.exp ) ).toBeGTE( 115 ); // at least 115 minutes
				expect( dateDiff( "n", now(), decoded.payload.exp ) ).toBeLTE( 125 ); // at most 125 minutes
			});

			it( "signs with PS256 algorithm", function() {
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
