package org.lucee.extension.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Generates a BCrypt password hash.
 *
 * Usage:
 *   hash = BCryptHash( "password" )
 *   hash = BCryptHash( "password", 12 )
 *
 * Replaces GenerateBCryptHash() which is retained as a deprecated alias.
 * Same defaults (cost=10) — the rename is purely for naming consistency.
 */
public class BCryptHash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final SecureRandom RANDOM = new SecureRandom();
	public static final int DEFAULT_COST = 10;

	public static String call( PageContext pc, String input ) throws PageException {
		return call( pc, input, DEFAULT_COST );
	}

	public static String call( PageContext pc, String input, Number cost ) throws PageException {
		return generate( pc, input, cost );
	}

	/**
	 * Core implementation shared by BCryptHash and GenerateBCryptHash.
	 */
	public static String generate( PageContext pc, String input, Number cost ) throws PageException {
		try {
			int costFactor = cost != null ? cost.intValue() : DEFAULT_COST;

			// Validate cost factor
			if ( costFactor < 4 || costFactor > 31 ) {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "BCrypt cost factor must be between 4 and 31" );
			}

			// Generate salt (16 bytes)
			byte[] salt = new byte[16];
			RANDOM.nextBytes( salt );

			// Generate hash
			return OpenBSDBCrypt.generate( input.toCharArray(), salt, costFactor );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "BCryptHash", 1, "input", "Input is required", null );
		}

		String input = cast.toString( args[0] );
		Number cost = args.length > 1 && args[1] != null ? cast.toInteger( args[1] ) : DEFAULT_COST;

		return call( pc, input, cost );
	}
}
