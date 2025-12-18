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
 * Generates a BCrypt password hash (ACF compatible).
 *
 * Usage:
 *   hash = GenerateBCryptHash( "password" )
 *   hash = GenerateBCryptHash( "password", 12 )
 */
public class GenerateBCryptHash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final SecureRandom RANDOM = new SecureRandom();

	public static String call( PageContext pc, String input ) throws PageException {
		return call( pc, input, 10 );
	}

	public static String call( PageContext pc, String input, Number cost ) throws PageException {
		try {
			int costFactor = cost != null ? cost.intValue() : 10;

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
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
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
		Number cost = args.length > 1 && args[1] != null ? cast.toInteger( args[1] ) : 10;

		return call( pc, input, cost );
	}
}
