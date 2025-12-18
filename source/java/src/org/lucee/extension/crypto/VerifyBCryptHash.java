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
 */
public class VerifyBCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Boolean call( PageContext pc, String input, String hash ) throws PageException {
		try {
			return OpenBSDBCrypt.checkPassword( hash, input.toCharArray() );
		}
		catch ( Exception e ) {
			// Invalid hash format or other error
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

		return call( pc, input, hash );
	}
}
