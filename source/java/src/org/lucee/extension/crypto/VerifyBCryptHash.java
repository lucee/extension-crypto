package org.lucee.extension.crypto;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Verifies a password against a BCrypt hash (ACF compatible).
 *
 * Usage:
 *   isValid = VerifyBCryptHash( "password", hash )
 *   isValid = VerifyBCryptHash( "password", hash, true )  // throws on invalid hash format
 */
public class VerifyBCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String input, String hash ) throws PageException {
		return call( pc, input, hash, false );
	}

	public static Object call( PageContext pc, String input, String hash, Boolean throwOnError ) throws PageException {
		boolean shouldThrow = throwOnError != null && throwOnError;
		try {
			return OpenBSDBCrypt.checkPassword( hash, input.toCharArray() );
		}
		catch ( Exception e ) {
			if ( shouldThrow ) {
				throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
			}
			return false;
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "VerifyBCryptHash", 2, "hash", "Input and hash are required", null );
		}

		String input = cast.toString( args[0] );
		String hash = cast.toString( args[1] );
		Boolean throwOnError = args.length > 2 && args[2] != null ? cast.toBoolean( args[2] ) : false;

		return call( pc, input, hash, throwOnError );
	}
}
