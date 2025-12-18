package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.bouncycastle.crypto.generators.SCrypt;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Verifies a password against an SCrypt hash (ACF compatible).
 *
 * Usage:
 *   isValid = VerifySCryptHash( "password", hash )
 */
public class VerifySCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Boolean call( PageContext pc, String input, String hash ) throws PageException {
		try {
			// Parse the hash string
			ParsedHash parsed = parseHash( hash );
			if ( parsed == null ) {
				return false;
			}

			// Regenerate hash with same parameters
			byte[] testHash = SCrypt.generate(
				input.getBytes( StandardCharsets.UTF_8 ),
				parsed.salt,
				parsed.n, parsed.r, parsed.p,
				parsed.hash.length
			);

			// Constant-time comparison
			return constantTimeEquals( testHash, parsed.hash );
		}
		catch ( Exception e ) {
			return false;
		}
	}

	/**
	 * Parse SCrypt hash string.
	 * Format: $scrypt$ln=14,r=8,p=1$salt$hash
	 */
	private static ParsedHash parseHash( String hash ) {
		if ( hash == null || !hash.startsWith( "$scrypt$" ) ) {
			return null;
		}

		String[] parts = hash.split( "\\$" );
		if ( parts.length < 5 ) {
			return null;
		}

		ParsedHash result = new ParsedHash();

		// Parse parameters (parts[2]) - ln=14,r=8,p=1
		String[] params = parts[2].split( "," );
		for ( String param : params ) {
			String[] kv = param.split( "=" );
			if ( kv.length != 2 ) continue;

			switch ( kv[0] ) {
				case "ln":
					result.n = (int) Math.pow( 2, Integer.parseInt( kv[1] ) );
					break;
				case "r":
					result.r = Integer.parseInt( kv[1] );
					break;
				case "p":
					result.p = Integer.parseInt( kv[1] );
					break;
			}
		}

		// Parse salt (parts[3])
		result.salt = Base64.getDecoder().decode( addPadding( parts[3] ) );

		// Parse hash (parts[4])
		result.hash = Base64.getDecoder().decode( addPadding( parts[4] ) );

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
		int n;
		int r;
		int p;
		byte[] salt;
		byte[] hash;
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "VerifySCryptHash", 2, "hash", "Input and hash are required", null );
		}

		String input = cast.toString( args[0] );
		String hash = cast.toString( args[1] );

		return call( pc, input, hash );
	}
}
