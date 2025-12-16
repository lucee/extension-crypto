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
		if ( args.length < 2 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "ValidateKeyPair", 2, "publicKey", "Both privateKey and publicKey are required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String privateKey = eng.getCastUtil().toString( args[0] );
		String publicKey = eng.getCastUtil().toString( args[1] );

		return call( pc, privateKey, publicKey );
	}
}
