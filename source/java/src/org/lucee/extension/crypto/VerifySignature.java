package org.lucee.extension.crypto;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Verifies a digital signature using a public key.
 *
 * Usage:
 *   isValid = VerifySignature( data="data to verify", signature=base64Signature, publicKey=pemPublicKey )
 */
public class VerifySignature extends BIF {

	private static final long serialVersionUID = 1L;

	public static Boolean call( PageContext pc, Object data, String signatureBase64, Object publicKey, String algorithm )
			throws PageException {
		try {
			CryptoUtil.ensureProvider();

			// Get bytes from data
			byte[] dataBytes = CryptoUtil.toBytes( data );

			// Decode signature
			byte[] signatureBytes = Base64.getDecoder().decode( signatureBase64 );

			// Parse public key
			PublicKey pubKey;
			if ( publicKey instanceof PublicKey ) {
				pubKey = (PublicKey) publicKey;
			}
			else {
				String pemStr = CFMLEngineFactory.getInstance().getCastUtil().toString( publicKey );
				pubKey = CryptoUtil.parsePublicKey( pemStr );
			}

			// Determine algorithm if not specified
			if ( algorithm == null || algorithm.trim().isEmpty() ) {
				algorithm = CryptoUtil.getSignatureAlgorithm( pubKey );
			}
			else {
				algorithm = algorithm.trim();
			}

			// Verify signature
			Signature verifier = Signature.getInstance( algorithm, "BC" );
			verifier.initVerify( pubKey );
			verifier.update( dataBytes );

			return verifier.verify( signatureBytes );
		}
		catch ( java.security.SignatureException e ) {
			// Invalid signature - this is expected for mismatched signatures
			return false;
		}
		catch ( Exception e ) {
			// Unexpected error (bad key, wrong algorithm, etc) - rethrow so caller knows something is wrong
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 3 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "VerifySignature", 3, "publicKey",
				"data, signature, and publicKey are required", null
			);
		}

		Object data = args[0];
		String signature = cast.toString( args[1] );
		Object publicKey = args[2];
		String algorithm = args.length > 3 && args[3] != null ? cast.toString( args[3] ) : null;

		return call( pc, data, signature, publicKey, algorithm );
	}
}
