package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.digests.Blake2bDigest;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Generates a Blake2b hash.
 *
 * Blake2b is optimized for 64-bit platforms and is faster than SHA-256 while being at least as secure.
 *
 * Usage:
 *   hash = GenerateBlake2bHash( "data" )
 *   hash = GenerateBlake2bHash( "data", 32 )           // output length in bytes (1-64)
 *   hash = GenerateBlake2bHash( "data", 32, keyBytes ) // keyed mode (MAC)
 *
 * Returns: hex-encoded hash string
 */
public class GenerateBlake2bHash extends BIF {

	private static final long serialVersionUID = 1L;
	private static final int DEFAULT_OUTPUT_LENGTH = 32;  // 256 bits
	private static final int MAX_OUTPUT_LENGTH = 64;      // 512 bits max for Blake2b

	public static String call( PageContext pc, Object input ) throws PageException {
		return call( pc, input, DEFAULT_OUTPUT_LENGTH, null );
	}

	public static String call( PageContext pc, Object input, Number outputLength ) throws PageException {
		return call( pc, input, outputLength, null );
	}

	public static String call( PageContext pc, Object input, Number outputLength, Object key ) throws PageException {
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
			if ( outLen < 1 || outLen > MAX_OUTPUT_LENGTH ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Output length must be between 1 and " + MAX_OUTPUT_LENGTH + " bytes" );
			}

			// Convert key to bytes if provided
			byte[] keyBytes = null;
			if ( key != null ) {
				if ( key instanceof byte[] ) {
					keyBytes = (byte[]) key;
				} else {
					keyBytes = eng.getCastUtil().toString( key ).getBytes( StandardCharsets.UTF_8 );
				}
				if ( keyBytes.length > 64 ) {
					throw eng.getExceptionUtil().createApplicationException(
						"Key length must be at most 64 bytes for Blake2b" );
				}
			}

			// Create digest
			Blake2bDigest digest;
			if ( keyBytes != null ) {
				digest = new Blake2bDigest( keyBytes, outLen, null, null );
			} else {
				digest = new Blake2bDigest( outLen * 8 );  // constructor takes bits
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
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "GenerateBlake2bHash", 1, "input", "Input is required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Object input = args[0];
		Number outputLength = args.length > 1 && args[1] != null ? eng.getCastUtil().toInteger( args[1] ) : DEFAULT_OUTPUT_LENGTH;
		Object key = args.length > 2 ? args[2] : null;

		return call( pc, input, outputLength, key );
	}
}
