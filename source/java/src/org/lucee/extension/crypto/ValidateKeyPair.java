package org.lucee.extension.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Validates that a public and private key form a matching pair.
 *
 * Usage:
 *   isValid = ValidateKeyPair( privateKey=pemPrivate, publicKey=pemPublic )
 */
public class ValidateKeyPair extends BIF {

	private static final long serialVersionUID = 1L;
	private static final byte[] TEST_DATA = "test-data-for-validation".getBytes();

	public static Boolean call( PageContext pc, String privateKeyPem, String publicKeyPem ) throws PageException {
		try {
			PrivateKey privateKey = CryptoUtil.parsePrivateKey( privateKeyPem );
			PublicKey publicKey = CryptoUtil.parsePublicKey( publicKeyPem );

			// Determine signature algorithm based on key type
			String algorithm = CryptoUtil.getSignatureAlgorithm( privateKey );

			// Sign with private key
			Signature signer = Signature.getInstance( algorithm, "BC" );
			signer.initSign( privateKey );
			signer.update( TEST_DATA );
			byte[] signature = signer.sign();

			// Verify with public key
			Signature verifier = Signature.getInstance( algorithm, "BC" );
			verifier.initVerify( publicKey );
			verifier.update( TEST_DATA );

			return verifier.verify( signature );
		}
		catch ( Exception e ) {
			// Keys don't match or are invalid
			return false;
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "ValidateKeyPair", 2, "publicKey", "Both privateKey and publicKey are required", null );
		}

		String privateKey = cast.toString( args[0] );
		String publicKey = cast.toString( args[1] );

		return call( pc, privateKey, publicKey );
	}
}
