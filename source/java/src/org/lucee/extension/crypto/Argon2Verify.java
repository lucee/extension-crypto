package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.lucee.extension.crypto.util.CryptoUtil;
import org.bouncycastle.crypto.params.Argon2Parameters;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Verifies a password against an Argon2 hash.
 *
 * Usage:
 *   isValid = Argon2Verify( "password", hash )
 *   isValid = Argon2Verify( "password", hash, true )  // throws on invalid hash format
 *
 * Replaces Argon2CheckHash() and VerifyArgon2Hash(), both retained as deprecated aliases.
 */
public class Argon2Verify extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String input, String hash ) throws PageException {
		return call( pc, input, hash, false );
	}

	public static Object call( PageContext pc, String input, String hash, Boolean throwOnError ) throws PageException {
		return verify( pc, input, hash, throwOnError );
	}

	/**
	 * Core implementation shared by Argon2Verify, Argon2CheckHash and VerifyArgon2Hash.
	 */
	public static Object verify( PageContext pc, String input, String hash, Boolean throwOnError ) throws PageException {
		boolean shouldThrow = throwOnError != null && throwOnError;
		try {
			// Parse the hash string
			ParsedHash parsed = parseHash( hash );
			if ( parsed == null ) {
				if ( shouldThrow ) {
					throw CFMLEngineFactory.getInstance().getExceptionUtil()
						.createApplicationException( "Invalid Argon2 hash format" );
				}
				return false;
			}

			// Regenerate hash with same parameters
			Argon2Parameters.Builder builder = new Argon2Parameters.Builder( parsed.type )
				.withSalt( parsed.salt )
				.withParallelism( parsed.parallelism )
				.withMemoryAsKB( parsed.memory )
				.withIterations( parsed.iterations )
				.withVersion( parsed.version );

			Argon2Parameters params = builder.build();

			Argon2BytesGenerator generator = new Argon2BytesGenerator();
			generator.init( params );

			byte[] testHash = new byte[parsed.hash.length];
			generator.generateBytes( input.getBytes( StandardCharsets.UTF_8 ), testHash );

			// Constant-time comparison
			return CryptoUtil.constantTimeEquals( testHash, parsed.hash );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			if ( shouldThrow ) {
				throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
			}
			return false;
		}
	}

	/**
	 * Parse PHC format hash string.
	 * Format: $argon2id$v=19$m=65536,t=3,p=1$salt$hash
	 */
	private static ParsedHash parseHash( String hash ) {
		if ( hash == null || !hash.startsWith( "$argon2" ) ) {
			return null;
		}

		String[] parts = hash.split( "\\$" );
		if ( parts.length < 5 ) {
			return null;
		}

		ParsedHash result = new ParsedHash();

		// Parse variant (parts[1])
		switch ( parts[1] ) {
			case "argon2d":
				result.type = Argon2Parameters.ARGON2_d;
				break;
			case "argon2i":
				result.type = Argon2Parameters.ARGON2_i;
				break;
			case "argon2id":
				result.type = Argon2Parameters.ARGON2_id;
				break;
			default:
				return null;
		}

		// Parse version (parts[2]) - v=19
		if ( parts[2].startsWith( "v=" ) ) {
			result.version = Integer.parseInt( parts[2].substring( 2 ) );
		}
		else {
			result.version = Argon2Parameters.ARGON2_VERSION_13;
		}

		// Parse parameters (parts[3]) - m=65536,t=3,p=1
		String[] params = parts[3].split( "," );
		boolean hasMemory = false, hasIterations = false, hasParallelism = false;
		for ( String param : params ) {
			String[] kv = param.split( "=" );
			if ( kv.length != 2 ) return null;

			switch ( kv[0] ) {
				case "m":
					result.memory = Integer.parseInt( kv[1] );
					hasMemory = true;
					break;
				case "t":
					result.iterations = Integer.parseInt( kv[1] );
					hasIterations = true;
					break;
				case "p":
					result.parallelism = Integer.parseInt( kv[1] );
					hasParallelism = true;
					break;
			}
		}

		if ( !hasMemory || !hasIterations || !hasParallelism ) return null;

		// Parse salt (parts[4])
		result.salt = CryptoUtil.base64DecodeLenient( parts[4] );

		// Parse hash (parts[5])
		result.hash = CryptoUtil.base64DecodeLenient( parts[5] );

		return result;
	}

	private static class ParsedHash {
		int type;
		int version;
		int memory;
		int iterations;
		int parallelism;
		byte[] salt;
		byte[] hash;
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "Argon2Verify", 2, "hash", "Input and hash are required", null );
		}

		String input = cast.toString( args[0] );
		String hash = cast.toString( args[1] );
		Boolean throwOnError = args.length > 2 && args[2] != null ? cast.toBoolean( args[2] ) : false;

		return call( pc, input, hash, throwOnError );
	}
}
