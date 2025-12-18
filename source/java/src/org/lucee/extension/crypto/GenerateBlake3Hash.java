package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.params.Blake3Parameters;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Generates a Blake3 hash.
 *
 * Blake3 is the latest in the Blake family - very fast, parallelizable, and supports
 * arbitrary output lengths (XOF - extendable output function).
 *
 * Usage:
 *   hash = GenerateBlake3Hash( "data" )
 *   hash = GenerateBlake3Hash( "data", 32 )                      // output length in bytes
 *   hash = GenerateBlake3Hash( "data", 32, keyBytes )            // keyed mode (MAC)
 *   hash = GenerateBlake3Hash( "data", 32, "", "MyApp context" ) // key derivation mode
 *
 * Returns: hex-encoded hash string
 */
public class GenerateBlake3Hash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final int DEFAULT_OUTPUT_LENGTH = 32;  // 256 bits

	public static String call( PageContext pc, Object input ) throws PageException {
		return call( pc, input, DEFAULT_OUTPUT_LENGTH, null, null );
	}

	public static String call( PageContext pc, Object input, Number outputLength ) throws PageException {
		return call( pc, input, outputLength, null, null );
	}

	public static String call( PageContext pc, Object input, Number outputLength, Object key ) throws PageException {
		return call( pc, input, outputLength, key, null );
	}

	public static String call( PageContext pc, Object input, Number outputLength, Object key, String context ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Convert input to bytes
			byte[] inputBytes;
			if ( input instanceof byte[] ) {
				inputBytes = (byte[]) input;
			} else {
				inputBytes = eng.getCastUtil().toString( input ).getBytes( StandardCharsets.UTF_8 );
			}

			// Validate output length
			int outLen = outputLength != null ? outputLength.intValue() : DEFAULT_OUTPUT_LENGTH;
			if ( outLen < 1 ) {
				throw eng.getExceptionUtil().createApplicationException( "Output length must be at least 1 byte" );
			}

			// Convert key to bytes if provided
			byte[] keyBytes = null;
			if ( key != null ) {
				if ( key instanceof byte[] ) {
					keyBytes = (byte[]) key;
				} else {
					String keyStr = eng.getCastUtil().toString( key );
					if ( !keyStr.isEmpty() ) {
						keyBytes = keyStr.getBytes( StandardCharsets.UTF_8 );
					}
				}
				if ( keyBytes != null && keyBytes.length != 32 ) {
					throw eng.getExceptionUtil().createApplicationException(
						"Key must be exactly 32 bytes for Blake3 keyed mode" );
				}
			}

			// Create digest based on mode
			Blake3Digest digest = new Blake3Digest( outLen * 8 );  // constructor takes bits
			if ( context != null && !context.isEmpty() ) {
				// Key derivation mode
				digest.init( Blake3Parameters.context( context.getBytes( StandardCharsets.UTF_8 ) ) );
			} else if ( keyBytes != null ) {
				// Keyed mode (MAC)
				digest.init( Blake3Parameters.key( keyBytes ) );
			}

			// Hash
			digest.update( inputBytes, 0, inputBytes.length );
			byte[] hash = new byte[outLen];
			digest.doFinal( hash, 0 );

			// Return hex encoded
			return bytesToHex( hash );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static String bytesToHex( byte[] bytes ) {
		StringBuilder sb = new StringBuilder( bytes.length * 2 );
		for ( byte b : bytes ) {
			sb.append( String.format( "%02x", b ) );
		}
		return sb.toString();
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "GenerateBlake3Hash", 1, "input", "Input is required", null );
		}

		Object input = args[0];
		Number outputLength = args.length > 1 && args[1] != null ? cast.toInteger( args[1] ) : DEFAULT_OUTPUT_LENGTH;
		Object key = args.length > 2 ? args[2] : null;
		String context = args.length > 3 && args[3] != null ? cast.toString( args[3] ) : null;

		return call( pc, input, outputLength, key, context );
	}
}
