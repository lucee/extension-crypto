component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateSelfSignedCertificate", function() {

			it( "generates a self-signed certificate with individual keys", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var cert = GenerateSelfSignedCertificate(
					privateKey = keyPair.private,
					publicKey = keyPair.public,
					subject = "CN=localhost, O=Test, C=AU"
				);

				expect( cert ).toInclude( "-----BEGIN CERTIFICATE-----" );
			});

			it( "generates a self-signed certificate with keyPair struct", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var cert = GenerateSelfSignedCertificate(
					keyPair = keyPair,
					subject = "CN=test.example.com"
				);

				expect( cert ).toInclude( "-----BEGIN CERTIFICATE-----" );
			});

			it( "generates certificate with custom validity", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var cert = GenerateSelfSignedCertificate(
					keyPair = keyPair,
					subject = "CN=localhost",
					validityDays = 730
				);

				var info = CertificateInfo( cert );
				var daysDiff = dateDiff( "d", info.validFrom, info.validTo );

				expect( daysDiff ).toBe( 730 );
			});

			it( "generates certificate with EC key", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var cert = GenerateSelfSignedCertificate(
					keyPair = keyPair,
					subject = "CN=ec-test"
				);

				var info = CertificateInfo( cert );
				expect( info.publicKeyAlgorithm ).toBe( "EC" );
			});

		});

		describe( "CertificateInfo", function() {

			it( "extracts certificate information", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var cert = GenerateSelfSignedCertificate(
					keyPair = keyPair,
					subject = "CN=localhost, O=My Org, C=AU"
				);

				var info = CertificateInfo( cert );

				expect( info ).toHaveKey( "subject" );
				expect( info ).toHaveKey( "issuer" );
				expect( info ).toHaveKey( "validFrom" );
				expect( info ).toHaveKey( "validTo" );
				expect( info ).toHaveKey( "algorithm" );
				expect( info ).toHaveKey( "fingerprint" );
				expect( info.selfSigned ).toBeTrue();
			});

			it( "includes fingerprints", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var cert = GenerateSelfSignedCertificate(
					keyPair = keyPair,
					subject = "CN=test"
				);

				var info = CertificateInfo( cert );

				expect( info.fingerprint ).toHaveKey( "sha1" );
				expect( info.fingerprint ).toHaveKey( "sha256" );
				expect( info.fingerprint.sha1 ).toMatch( "^[A-F0-9:]+$" );
			});

		});

		describe( "PemToCertificate and CertificateToPem", function() {

			it( "roundtrips certificate", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var originalPem = GenerateSelfSignedCertificate(
					keyPair = keyPair,
					subject = "CN=roundtrip"
				);

				var certObj = PemToCertificate( originalPem );
				var newPem = CertificateToPem( certObj );

				// Both should be valid PEM
				expect( originalPem ).toInclude( "-----BEGIN CERTIFICATE-----" );
				expect( newPem ).toInclude( "-----BEGIN CERTIFICATE-----" );

				// Info should match
				var info1 = CertificateInfo( originalPem );
				var info2 = CertificateInfo( newPem );
				expect( info1.serialNumber ).toBe( info2.serialNumber );
			});

		});

	}

}
