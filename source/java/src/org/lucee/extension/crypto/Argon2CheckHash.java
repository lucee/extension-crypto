package org.lucee.extension.crypto;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Deprecated: use Argon2Verify() instead.
 *
 * Retained for backwards compatibility with extension-argon2.
 * Also aliased as VerifyArgon2Hash in the FLD.
 * Delegates all verification to Argon2Verify.verify().
 */
public class Argon2CheckHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String input, String hash ) throws PageException {
		return Argon2Verify.verify( pc, input, hash, false );
	}

	public static Object call( PageContext pc, String input, String hash, Boolean throwOnError ) throws PageException {
		return Argon2Verify.verify( pc, input, hash, throwOnError );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "Argon2CheckHash", 2, "hash", "Input and hash are required", null );
		}

		String input = cast.toString( args[0] );
		String hash = cast.toString( args[1] );
		Boolean throwOnError = args.length > 2 && args[2] != null ? cast.toBoolean( args[2] ) : false;

		return Argon2Verify.verify( pc, input, hash, throwOnError );
	}
}
