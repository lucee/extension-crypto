package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.generators.SCrypt;
import org.lucee.extension.crypto.util.CryptoUtil;

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
 *   isValid = VerifySCryptHash( "password", hash, true )  // throws on invalid hash format
 */
public class VerifySCryptHash extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String input, String hash ) throws PageException {
		return call( pc, input, hash, false );
	}

	public static Object call( PageContext pc, String input, String hash, Boolean throwOnError ) throws PageException {
		boolean shouldThrow = throwOnError != null && throwOnError;
		try {
			// Parse the hash string
			ParsedHash parsed = parseHash( hash );
			if ( parsed == null ) {
				if ( shouldThrow ) {
					throw CFMLEngineFactory.getInstance().getExceptionUtil()
						.createApplicationException( "Invalid SCrypt hash format" );
				}
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
			return CryptoUtil.constantTimeEquals( testHash, parsed.hash );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			if ( shouldThrow ) {
				throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
			}
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
		result.salt = CryptoUtil.base64DecodeLenient( parts[3] );

		// Parse hash (parts[4])
		result.hash = CryptoUtil.base64DecodeLenient( parts[4] );

		return result;
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
		Boolean throwOnError = args.length > 2 && args[2] != null ? cast.toBoolean( args[2] ) : false;

		return call( pc, input, hash, throwOnError );
	}
}
