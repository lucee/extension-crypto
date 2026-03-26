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
import lucee.runtime.util.Cast;

/**
 * Generates an SCrypt password hash.
 *
 * Usage:
 *   hash = SCryptHash( "password" )
 *   hash = SCryptHash( "password", 16384, 8, 1 )
 *
 * Replaces GenerateSCryptHash() which is retained as a deprecated alias.
 * Same defaults (N=16384, r=8, p=1) — the rename is purely for naming consistency.
 */
public class SCryptHash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int SALT_LENGTH = 16;
	private static final int HASH_LENGTH = 32;

	public static final int DEFAULT_N = 16384;
	public static final int DEFAULT_R = 8;
	public static final int DEFAULT_P = 1;

	public static String call( PageContext pc, String input ) throws PageException {
		return call( pc, input, DEFAULT_N, DEFAULT_R, DEFAULT_P );
	}

	public static String call( PageContext pc, String input, Number costParameter ) throws PageException {
		return call( pc, input, costParameter, DEFAULT_R, DEFAULT_P );
	}

	public static String call( PageContext pc, String input, Number costParameter, Number blockSize ) throws PageException {
		return call( pc, input, costParameter, blockSize, DEFAULT_P );
	}

	public static String call( PageContext pc, String input, Number costParameter, Number blockSize, Number parallelization )
			throws PageException {
		return generate( pc, input, costParameter, blockSize, parallelization );
	}

	/**
	 * Core implementation shared by SCryptHash and GenerateSCryptHash.
	 */
	public static String generate( PageContext pc, String input, Number costParameter, Number blockSize, Number parallelization )
			throws PageException {
		try {
			int n = costParameter != null ? costParameter.intValue() : DEFAULT_N;
			int r = blockSize != null ? blockSize.intValue() : DEFAULT_R;
			int p = parallelization != null ? parallelization.intValue() : DEFAULT_P;

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

			// Format: $scrypt$ln=14,r=8,p=1$salt$hash
			return formatHash( n, r, p, salt, hash );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	/**
	 * Format hash in a standard format.
	 * Format: $scrypt$ln=14,r=8,p=1$salt$hash
	 * Where ln is log2(N)
	 */
	static String formatHash( int n, int r, int p, byte[] salt, byte[] hash ) {
		int ln = Integer.numberOfTrailingZeros( n );
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
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "SCryptHash", 1, "input", "Input is required", null );
		}

		String input = cast.toString( args[0] );
		Number n = args.length > 1 && args[1] != null ? cast.toInteger( args[1] ) : DEFAULT_N;
		Number r = args.length > 2 && args[2] != null ? cast.toInteger( args[2] ) : DEFAULT_R;
		Number p = args.length > 3 && args[3] != null ? cast.toInteger( args[3] ) : DEFAULT_P;

		return call( pc, input, n, r, p );
	}
}
