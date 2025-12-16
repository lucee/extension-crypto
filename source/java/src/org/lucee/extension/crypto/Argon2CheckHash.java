package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Verifies a password against an Argon2 hash.
 * Also aliased as VerifyArgon2Hash for consistency.
 *
 * Usage:
 *   isValid = Argon2CheckHash( "password", hash )
 *   isValid = VerifyArgon2Hash( "password", hash )
 */
public class Argon2CheckHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Boolean call( PageContext pc, String input, String hash ) throws PageException {
		try {
			// Parse the hash string
			ParsedHash parsed = parseHash( hash );
			if ( parsed == null ) {
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
			return constantTimeEquals( testHash, parsed.hash );
		}
		catch ( Exception e ) {
			// Any parsing or generation error means invalid hash
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
		for ( String param : params ) {
			String[] kv = param.split( "=" );
			if ( kv.length != 2 ) continue;

			switch ( kv[0] ) {
				case "m":
					result.memory = Integer.parseInt( kv[1] );
					break;
				case "t":
					result.iterations = Integer.parseInt( kv[1] );
					break;
				case "p":
					result.parallelism = Integer.parseInt( kv[1] );
					break;
			}
		}

		// Parse salt (parts[4])
		result.salt = Base64.getDecoder().decode( addPadding( parts[4] ) );

		// Parse hash (parts[5])
		result.hash = Base64.getDecoder().decode( addPadding( parts[5] ) );

		return result;
	}

	/**
	 * Add padding to Base64 string if needed.
	 */
	private static String addPadding( String base64 ) {
		int padding = ( 4 - base64.length() % 4 ) % 4;
		StringBuilder sb = new StringBuilder( base64 );
		for ( int i = 0; i < padding; i++ ) {
			sb.append( '=' );
		}
		return sb.toString();
	}

	/**
	 * Constant-time byte array comparison to prevent timing attacks.
	 */
	private static boolean constantTimeEquals( byte[] a, byte[] b ) {
		if ( a.length != b.length ) {
			return false;
		}
		int result = 0;
		for ( int i = 0; i < a.length; i++ ) {
			result |= a[i] ^ b[i];
		}
		return result == 0;
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
		if ( args.length < 2 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "Argon2CheckHash", 2, "hash", "Input and hash are required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String input = eng.getCastUtil().toString( args[0] );
		String hash = eng.getCastUtil().toString( args[1] );

		return call( pc, input, hash );
	}
}
