package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Generates an Argon2 password hash.
 *
 * Usage:
 *   hash = GenerateArgon2Hash( "password" )
 *   hash = GenerateArgon2Hash( "password", "argon2id", 4, 65536, 3 )
 *
 * Defaults: argon2id, parallelism=4, memory=65536 KB (64MB), iterations=3
 * These follow OWASP recommendations for password hashing.
 */
public class GenerateArgon2Hash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int HASH_LENGTH = 32;
	private static final int SALT_LENGTH = 16;

	// Secure defaults per OWASP recommendations
	private static final String DEFAULT_VARIANT = "argon2id";
	private static final int DEFAULT_PARALLELISM = 4;
	private static final int DEFAULT_MEMORY = 65536; // 64 MB
	private static final int DEFAULT_ITERATIONS = 3;

	public static String call( PageContext pc, String input ) throws PageException {
		return call( pc, input, DEFAULT_VARIANT, DEFAULT_PARALLELISM, DEFAULT_MEMORY, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant ) throws PageException {
		return call( pc, input, variant, DEFAULT_PARALLELISM, DEFAULT_MEMORY, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant, Number parallelismFactor ) throws PageException {
		return call( pc, input, variant, parallelismFactor, DEFAULT_MEMORY, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant, Number parallelismFactor, Number memoryCost ) throws PageException {
		return call( pc, input, variant, parallelismFactor, memoryCost, DEFAULT_ITERATIONS );
	}

	public static String call( PageContext pc, String input, String variant, Number parallelismFactor,
							   Number memoryCost, Number iterations ) throws PageException {
		try {
			// Parse parameters
			int type = parseVariant( variant );
			int parallelism = parallelismFactor != null ? parallelismFactor.intValue() : 1;
			int memory = memoryCost != null ? memoryCost.intValue() : 8;
			int iters = iterations != null ? iterations.intValue() : 8;

			// Validate parameters
			if ( parallelism < 1 || parallelism > 10 ) {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Parallelism factor must be between 1 and 10" );
			}
			if ( memory < 8 || memory > 100000 ) {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Memory cost must be between 8 and 100000 KB" );
			}
			if ( iters < 1 || iters > 20 ) {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Iterations must be between 1 and 20" );
			}

			// Generate salt
			byte[] salt = new byte[SALT_LENGTH];
			RANDOM.nextBytes( salt );

			// Build parameters
			Argon2Parameters.Builder builder = new Argon2Parameters.Builder( type )
				.withSalt( salt )
				.withParallelism( parallelism )
				.withMemoryAsKB( memory )
				.withIterations( iters );

			Argon2Parameters params = builder.build();

			// Generate hash
			Argon2BytesGenerator generator = new Argon2BytesGenerator();
			generator.init( params );

			byte[] hash = new byte[HASH_LENGTH];
			generator.generateBytes( input.getBytes( StandardCharsets.UTF_8 ), hash );

			// Format output in PHC string format
			return formatHash( type, memory, iters, parallelism, salt, hash );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static int parseVariant( String variant ) throws PageException {
		if ( variant == null || variant.trim().isEmpty() ) {
			variant = DEFAULT_VARIANT;
		}

		switch ( variant.trim().toLowerCase() ) {
			case "argon2d":
				return Argon2Parameters.ARGON2_d;
			case "argon2i":
				return Argon2Parameters.ARGON2_i;
			case "argon2id":
				return Argon2Parameters.ARGON2_id;
			default:
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Unknown Argon2 variant: " + variant + ". Use argon2i, argon2d, or argon2id" );
		}
	}

	private static String variantName( int type ) {
		switch ( type ) {
			case Argon2Parameters.ARGON2_d:
				return "argon2d";
			case Argon2Parameters.ARGON2_i:
				return "argon2i";
			case Argon2Parameters.ARGON2_id:
				return "argon2id";
			default:
				return "argon2i";
		}
	}

	/**
	 * Format hash in PHC string format:
	 * $argon2id$v=19$m=65536,t=3,p=1$salt$hash
	 */
	private static String formatHash( int type, int memory, int iterations, int parallelism, byte[] salt, byte[] hash ) {
		StringBuilder sb = new StringBuilder();
		sb.append( "$" ).append( variantName( type ) );
		sb.append( "$v=" ).append( Argon2Parameters.ARGON2_VERSION_13 );
		sb.append( "$m=" ).append( memory );
		sb.append( ",t=" ).append( iterations );
		sb.append( ",p=" ).append( parallelism );
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
				.createFunctionException( pc, "GenerateArgon2Hash", 1, "input", "Input is required", null );
		}

		String input = cast.toString( args[0] );
		String variant = args.length > 1 && args[1] != null ? cast.toString( args[1] ) : DEFAULT_VARIANT;
		Number parallelism = args.length > 2 && args[2] != null ? cast.toInteger( args[2] ) : DEFAULT_PARALLELISM;
		Number memory = args.length > 3 && args[3] != null ? cast.toInteger( args[3] ) : DEFAULT_MEMORY;
		Number iterations = args.length > 4 && args[4] != null ? cast.toInteger( args[4] ) : DEFAULT_ITERATIONS;

		return call( pc, input, variant, parallelism, memory, iterations );
	}
}
