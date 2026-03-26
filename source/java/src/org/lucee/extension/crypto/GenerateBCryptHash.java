package org.lucee.extension.crypto;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Deprecated: use BCryptHash() instead.
 *
 * Retained for backwards compatibility.
 * Delegates all hashing to BCryptHash.generate().
 */
public class GenerateBCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, String input ) throws PageException {
		return BCryptHash.generate( pc, input, BCryptHash.DEFAULT_COST );
	}

	public static String call( PageContext pc, String input, Number cost ) throws PageException {
		return BCryptHash.generate( pc, input, cost );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "GenerateBCryptHash", 1, "input", "Input is required", null );
		}

		String input = cast.toString( args[0] );
		Number cost = args.length > 1 && args[1] != null ? cast.toInteger( args[1] ) : BCryptHash.DEFAULT_COST;

		return BCryptHash.generate( pc, input, cost );
	}
}
