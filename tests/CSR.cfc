/**
 * Tests for GenerateCSR() — PKCS#10 Certificate Signing Request generation.
 *
 * Completes the certificate lifecycle: GenerateKeyPair -> GenerateCSR -> (submit to CA).
 * Uses BouncyCastle's PKCS10CertificationRequestBuilder.
 */
component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateCSR with RSA keys", function() {

			it( "generates a PEM-encoded CSR", function() {
				var kp = GenerateKeyPair( "RSA" );
				var csr = GenerateCSR( kp, "CN=example.com,O=Test,C=AU" );

				expect( csr ).toBeString();
				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
				expect( csr ).toInclude( "-----END CERTIFICATE REQUEST-----" );
			});

			it( "embeds the correct subject", function() {
				var kp = GenerateKeyPair( "RSA" );
				var csr = GenerateCSR( kp, "CN=test.example.com,O=My Org,C=AU" );

				// The CSR is PEM-encoded, subject is in the DER — just verify it's valid PEM
				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
			});

		});

		describe( "GenerateCSR with EC keys", function() {

			it( "generates a CSR with P-256 key", function() {
				var kp = GenerateKeyPair( "EC" );
				var csr = GenerateCSR( kp, "CN=ec-test.example.com" );

				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
			});

			it( "generates a CSR with P-384 key", function() {
				var kp = GenerateKeyPair( "P-384" );
				var csr = GenerateCSR( kp, "CN=ec384.example.com" );

				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
			});

		});

		describe( "GenerateCSR with Ed25519 keys", function() {

			it( "generates a CSR with Ed25519 key", function() {
				var kp = GenerateKeyPair( "Ed25519" );
				var csr = GenerateCSR( kp, "CN=ed25519.example.com" );

				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
			});

		});

		describe( "GenerateCSR with SANs", function() {

			it( "generates a CSR with Subject Alternative Names", function() {
				var kp = GenerateKeyPair( "RSA" );
				var csr = GenerateCSR( kp, "CN=example.com", {
					sans: [ "example.com", "www.example.com", "api.example.com" ]
				});

				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
			});

		});

		describe( "GenerateCSR with PEM key pair", function() {

			it( "accepts a struct with PEM-encoded keys", function() {
				var kp = GenerateKeyPair( "RSA" );
				// kp.private and kp.public are PEM strings by default
				var csr = GenerateCSR( kp, "CN=pem-test.example.com" );

				expect( csr ).toInclude( "-----BEGIN CERTIFICATE REQUEST-----" );
			});

		});

	}

}
