package org.lucee.extension.crypto;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Converts a Java key object or Base64-encoded key to PEM format.
 *
 * Usage:
 *   pem = KeyToPem( javaKeyObject )
 *   pem = KeyToPem( base64Key, "RSA" )
 */
public class KeyToPem extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object key ) throws PageException {
		return call( pc, key, null );
	}

	public static String call( PageContext pc, Object key, String algorithm ) throws PageException {
		try {
			// If it's already a Key object
			if ( key instanceof Key ) {
				return CryptoUtil.toPem( key );
			}

			// If it's a string, try to interpret it
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			String keyStr = eng.getCastUtil().toString( key );

			// If it already looks like PEM, just return it
			if ( keyStr.contains( "-----BEGIN" ) ) {
				return keyStr;
			}

			// Assume it's Base64-encoded DER
			if ( algorithm == null || algorithm.isEmpty() ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Algorithm is required when converting Base64-encoded keys. Specify RSA, EC, etc."
				);
			}

			// Try to parse as private key first, then public key
			try {
				PrivateKey privKey = CryptoUtil.base64ToPrivateKey( keyStr, algorithm );
				return CryptoUtil.toPem( privKey );
			}
			catch ( Exception e ) {
				// Try as public key
				PublicKey pubKey = CryptoUtil.base64ToPublicKey( keyStr, algorithm );
				return CryptoUtil.toPem( pubKey );
			}
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
				.createFunctionException( pc, "KeyToPem", 1, "key", "Key is required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Object key = args[0];
		String algorithm = args.length > 1 && args[1] != null ? eng.getCastUtil().toString( args[1] ) : null;

		return call( pc, key, algorithm );
	}
}
