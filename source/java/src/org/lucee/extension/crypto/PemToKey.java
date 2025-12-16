package org.lucee.extension.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Parses a PEM-encoded key string into a Java key object.
 *
 * Usage:
 *   privateKey = PemToKey( pemPrivateKeyString )
 *   publicKey = PemToKey( pemPublicKeyString )
 */
public class PemToKey extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String pem ) throws PageException {
		try {
			Object result = CryptoUtil.parsePem( pem );

			// If it's a KeyPair, we need to determine which key to return
			// based on what was in the PEM (this shouldn't happen with proper PEM files)
			if ( result instanceof KeyPair ) {
				// Return the private key if available, otherwise public
				KeyPair kp = (KeyPair) result;
				return kp.getPrivate() != null ? kp.getPrivate() : kp.getPublic();
			}

			if ( result instanceof PrivateKey || result instanceof PublicKey ) {
				return result;
			}

			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createApplicationException( "PEM does not contain a key. Found: " + result.getClass().getSimpleName() );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "PemToKey", 1, "pem", "PEM string is required", null );
		}

		String pem = CFMLEngineFactory.getInstance().getCastUtil().toString( args[0] );
		return call( pc, pem );
	}
}
