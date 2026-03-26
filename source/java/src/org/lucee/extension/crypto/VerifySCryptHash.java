package org.lucee.extension.crypto;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Deprecated: use SCryptVerify() instead.
 *
 * Retained for backwards compatibility.
 * Delegates all verification to SCryptVerify.verify().
 */
public class VerifySCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String input, String hash ) throws PageException {
		return SCryptVerify.verify( pc, input, hash, false );
	}

	public static Object call( PageContext pc, String input, String hash, Boolean throwOnError ) throws PageException {
		return SCryptVerify.verify( pc, input, hash, throwOnError );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "VerifySCryptHash", 2, "hash", "Input and hash are required", null );
		}

		String input = cast.toString( args[0] );
		String hash = cast.toString( args[1] );
		Boolean throwOnError = args.length > 2 && args[2] != null ? cast.toBoolean( args[2] ) : false;

		return SCryptVerify.verify( pc, input, hash, throwOnError );
	}
}
