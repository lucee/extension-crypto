package org.lucee.extension.crypto;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Creates a digital signature using a private key.
 *
 * Usage:
 *   signature = GenerateSignature( data="data to sign", privateKey=pemPrivateKey )
 *   signature = GenerateSignature( data="data to sign", privateKey=pemPrivateKey, algorithm="SHA256withRSA" )
 */
public class GenerateSignature extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object data, Object privateKey, String algorithm ) throws PageException {
		try {
			CryptoUtil.ensureProvider();

			// Get bytes from data
			byte[] dataBytes = CryptoUtil.toBytes( data );

			// Parse private key
			PrivateKey privKey;
			if ( privateKey instanceof PrivateKey ) {
				privKey = (PrivateKey) privateKey;
			}
			else {
				String pemStr = CFMLEngineFactory.getInstance().getCastUtil().toString( privateKey );
				privKey = CryptoUtil.parsePrivateKey( pemStr );
			}

			// Determine algorithm if not specified
			if ( algorithm == null || algorithm.trim().isEmpty() ) {
				algorithm = CryptoUtil.getSignatureAlgorithm( privKey );
			}
			else {
				algorithm = algorithm.trim();
			}

			// Create signature
			Signature signer = Signature.getInstance( algorithm, "BC" );
			signer.initSign( privKey );
			signer.update( dataBytes );
			byte[] signature = signer.sign();

			// Return Base64-encoded signature
			return Base64.getEncoder().encodeToString( signature );
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "GenerateSignature", 2, "privateKey",
				"data and privateKey are required", null
			);
		}

		Object data = args[0];
		Object privateKey = args[1];
		String algorithm = args.length > 2 && args[2] != null ? eng.getCastUtil().toString( args[2] ) : null;

		return call( pc, data, privateKey, algorithm );
	}
}
