component extends="org.lucee.cfml.test.LuceeTestCase" labels="crypto" {

	function run( testResults, testBox ) {

		describe( "GenerateSignature and VerifySignature", function() {

			it( "signs and verifies with RSA key", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var data = "Data to sign";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( data, signature, keyPair.public );

				expect( signature ).toBeString();
				expect( isValid ).toBeTrue();
			});

			it( "signs and verifies with EC key", function() {
				var keyPair = GenerateKeyPair( "P-256" );
				var data = "Data to sign with EC";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( data, signature, keyPair.public );

				expect( isValid ).toBeTrue();
			});

			it( "signs and verifies with Ed25519 key", function() {
				var keyPair = GenerateKeyPair( "Ed25519" );
				var data = "Data to sign with EdDSA";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( data, signature, keyPair.public );

				expect( isValid ).toBeTrue();
			});

			it( "rejects tampered data", function() {
				var keyPair = GenerateKeyPair( "RSA-2048" );
				var data = "Original data";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( "Tampered data", signature, keyPair.public );

				expect( isValid ).toBeFalse();
			});

			it( "rejects wrong key", function() {
				var keyPair1 = GenerateKeyPair( "RSA-2048" );
				var keyPair2 = GenerateKeyPair( "RSA-2048" );
				var data = "Test data";

				var signature = GenerateSignature( data, keyPair1.private );
				var isValid = VerifySignature( data, signature, keyPair2.public );

				expect( isValid ).toBeFalse();
			});

			it( "signs and verifies with Dilithium3 key (post-quantum)", function() {
				var keyPair = GenerateKeyPair( "Dilithium3" );
				var data = "Data to sign with post-quantum Dilithium";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( data, signature, keyPair.public );

				expect( isValid ).toBeTrue();
			});

			it( "signs and verifies with Dilithium2 key", function() {
				var keyPair = GenerateKeyPair( "Dilithium2" );
				var data = "Data to sign with Dilithium2";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( data, signature, keyPair.public );

				expect( isValid ).toBeTrue();
			});

			it( "signs and verifies with Dilithium5 key", function() {
				var keyPair = GenerateKeyPair( "Dilithium5" );
				var data = "Data to sign with Dilithium5";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( data, signature, keyPair.public );

				expect( isValid ).toBeTrue();
			});

			it( "rejects tampered data with Dilithium", function() {
				var keyPair = GenerateKeyPair( "Dilithium3" );
				var data = "Original data";

				var signature = GenerateSignature( data, keyPair.private );
				var isValid = VerifySignature( "Tampered data", signature, keyPair.public );

				expect( isValid ).toBeFalse();
			});

		});

	}

}
