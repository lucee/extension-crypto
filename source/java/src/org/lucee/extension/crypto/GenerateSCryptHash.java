package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.bouncycastle.crypto.generators.SCrypt;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Generates an SCrypt password hash (ACF compatible).
 *
 * Usage:
 *   hash = GenerateSCryptHash( "password" )
 *   hash = GenerateSCryptHash( "password", 16384, 8, 1 )
 */
public class GenerateSCryptHash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int SALT_LENGTH = 16;
	private static final int HASH_LENGTH = 32;

	public static String call( PageContext pc, String input ) throws PageException {
		return call( pc, input, 16384, 8, 1 );
	}

	public static String call( PageContext pc, String input, Number costParameter ) throws PageException {
		return call( pc, input, costParameter, 8, 1 );
	}

	public static String call( PageContext pc, String input, Number costParameter, Number blockSize ) throws PageException {
		return call( pc, input, costParameter, blockSize, 1 );
	}

	public static String call( PageContext pc, String input, Number costParameter, Number blockSize, Number parallelization )
			throws PageException {
		try {
			int n = costParameter != null ? costParameter.intValue() : 16384;
			int r = blockSize != null ? blockSize.intValue() : 8;
			int p = parallelization != null ? parallelization.intValue() : 1;

			// Validate parameters
			if ( ( n & ( n - 1 ) ) != 0 || n < 2 ) {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Cost parameter (N) must be a power of 2 greater than 1" );
			}

			// Generate salt
			byte[] salt = new byte[SALT_LENGTH];
			RANDOM.nextBytes( salt );

			// Generate hash
			byte[] hash = SCrypt.generate(
				input.getBytes( StandardCharsets.UTF_8 ),
				salt,
				n, r, p,
				HASH_LENGTH
			);

			// Format: $scrypt$N$r$p$salt$hash
			return formatHash( n, r, p, salt, hash );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	/**
	 * Format hash in a standard format.
	 * Format: $scrypt$ln=14,r=8,p=1$salt$hash
	 * Where ln is log2(N)
	 */
	private static String formatHash( int n, int r, int p, byte[] salt, byte[] hash ) {
		int ln = (int) ( Math.log( n ) / Math.log( 2 ) );
		StringBuilder sb = new StringBuilder();
		sb.append( "$scrypt$" );
		sb.append( "ln=" ).append( ln );
		sb.append( ",r=" ).append( r );
		sb.append( ",p=" ).append( p );
		sb.append( "$" ).append( Base64.getEncoder().withoutPadding().encodeToString( salt ) );
		sb.append( "$" ).append( Base64.getEncoder().withoutPadding().encodeToString( hash ) );
		return sb.toString();
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "GenerateSCryptHash", 1, "input", "Input is required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String input = eng.getCastUtil().toString( args[0] );
		Number n = args.length > 1 && args[1] != null ? eng.getCastUtil().toInteger( args[1] ) : 16384;
		Number r = args.length > 2 && args[2] != null ? eng.getCastUtil().toInteger( args[2] ) : 8;
		Number p = args.length > 3 && args[3] != null ? eng.getCastUtil().toInteger( args[3] ) : 1;

		return call( pc, input, n, r, p );
	}
}
