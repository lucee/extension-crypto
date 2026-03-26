package org.lucee.extension.crypto;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Deprecated: use Argon2Hash() instead.
 *
 * Retained for backwards compatibility with extension-argon2.
 * Uses the old extension-argon2 defaults (argon2i, memory=8 KB, iterations=1, parallelism=1)
 * which are weaker than the OWASP-recommended defaults in Argon2Hash().
 *
 * Delegates all hashing to Argon2Hash.generate().
 */
public class GenerateArgon2Hash extends BIF {

	private static final long serialVersionUID = 1L;

	// Old extension-argon2 defaults — intentionally weak to preserve backwards compat
	private static final String DEFAULT_VARIANT = "argon2i";
	private static final int DEFAULT_PARALLELISM = 1;
	private static final int DEFAULT_MEMORY = 8;
	private static final int DEFAULT_ITERATIONS = 1;

	public static String call( PageContext pc, String input ) throws PageException {
		return Argon2Hash.generate( pc, input, DEFAULT_VARIANT, DEFAULT_PARALLELISM, DEFAULT_MEMORY, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant ) throws PageException {
		return Argon2Hash.generate( pc, input, variant, DEFAULT_PARALLELISM, DEFAULT_MEMORY, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant, Number parallelismFactor ) throws PageException {
		return Argon2Hash.generate( pc, input, variant, parallelismFactor, DEFAULT_MEMORY, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant, Number parallelismFactor, Number memoryCost ) throws PageException {
		return Argon2Hash.generate( pc, input, variant, parallelismFactor, memoryCost, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant, Number parallelismFactor,
							   Number memoryCost, Number iterations ) throws PageException {
		return Argon2Hash.generate( pc, input, variant, parallelismFactor, memoryCost, iterations );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "GenerateArgon2Hash", 1, "input", "Input is required", null );
		}

		String input = cast.toString( args[0] );
		String variant = args.length > 1 && args[1] != null ? cast.toString( args[1] ) : DEFAULT_VARIANT;
		Number parallelism = args.length > 2 && args[2] != null ? cast.toInteger( args[2] ) : DEFAULT_PARALLELISM;
		Number memory = args.length > 3 && args[3] != null ? cast.toInteger( args[3] ) : DEFAULT_MEMORY;
		Number iterations = args.length > 4 && args[4] != null ? cast.toInteger( args[4] ) : DEFAULT_ITERATIONS;

		return Argon2Hash.generate( pc, input, variant, parallelism, memory, iterations );
	}
}
