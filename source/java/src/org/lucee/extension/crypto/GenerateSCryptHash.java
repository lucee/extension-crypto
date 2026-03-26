package org.lucee.extension.crypto;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Deprecated: use SCryptHash() instead.
 *
 * Retained for backwards compatibility.
 * Delegates all hashing to SCryptHash.generate().
 */
public class GenerateSCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, String input ) throws PageException {
		return SCryptHash.generate( pc, input, SCryptHash.DEFAULT_N, SCryptHash.DEFAULT_R, SCryptHash.DEFAULT_P );
	}

	public static String call( PageContext pc, String input, Number costParameter ) throws PageException {
		return SCryptHash.generate( pc, input, costParameter, SCryptHash.DEFAULT_R, SCryptHash.DEFAULT_P );
	}

	public static String call( PageContext pc, String input, Number costParameter, Number blockSize ) throws PageException {
		return SCryptHash.generate( pc, input, costParameter, blockSize, SCryptHash.DEFAULT_P );
	}

	public static String call( PageContext pc, String input, Number costParameter, Number blockSize, Number parallelization )
			throws PageException {
		return SCryptHash.generate( pc, input, costParameter, blockSize, parallelization );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "GenerateSCryptHash", 1, "input", "Input is required", null );
		}

		String input = cast.toString( args[0] );
		Number n = args.length > 1 && args[1] != null ? cast.toInteger( args[1] ) : SCryptHash.DEFAULT_N;
		Number r = args.length > 2 && args[2] != null ? cast.toInteger( args[2] ) : SCryptHash.DEFAULT_R;
		Number p = args.length > 3 && args[3] != null ? cast.toInteger( args[3] ) : SCryptHash.DEFAULT_P;

		return SCryptHash.generate( pc, input, n, r, p );
	}
}
