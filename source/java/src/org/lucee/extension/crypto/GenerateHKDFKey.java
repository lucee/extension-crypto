package org.lucee.extension.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Generates derived key material using HKDF (HMAC-based Key Derivation Function).
 *
 * HKDF is used in TLS 1.3, Signal Protocol, and other modern cryptographic applications.
 * This is a one-shot function that performs both Extract and Expand phases.
 *
 * Usage:
 *   key = GenerateHKDFKey( algorithm, inputKeyMaterial, salt, info, outputLength )
 *   key = GenerateHKDFKey( "SHA256", secretBytes, saltBytes, "encryption key", 32 )
 *
 * Returns: binary (derived key material)
 */
public class GenerateHKDFKey extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String algorithm, Object inputKeyMaterial,
							   Object salt, Object info, Number outputLength ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Get digest
			Digest digest = CryptoUtil.getDigest( algorithm );
			if ( digest == null ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Unsupported algorithm: " + algorithm + ". Use SHA256, SHA384, or SHA512." );
			}

			// Convert IKM to bytes
			byte[] ikmBytes = CryptoUtil.toBytesOrNull( inputKeyMaterial );
			if ( ikmBytes == null || ikmBytes.length == 0 ) {
				throw eng.getExceptionUtil().createApplicationException( "Input key material is required" );
			}

			// Convert salt to bytes (optional)
			byte[] saltBytes = CryptoUtil.toBytesOrNull( salt );

			// Convert info to bytes (optional)
			byte[] infoBytes = CryptoUtil.toBytesOrNull( info );

			// Validate output length
			int outLen = outputLength != null ? outputLength.intValue() : 32;
			int maxLen = 255 * digest.getDigestSize();
			if ( outLen < 1 || outLen > maxLen ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Output length must be between 1 and " + maxLen + " bytes for " + algorithm );
			}

			// Create HKDF generator
			HKDFBytesGenerator hkdf = new HKDFBytesGenerator( digest );
			hkdf.init( new HKDFParameters( ikmBytes, saltBytes, infoBytes ) );

			// Generate output
			byte[] output = new byte[outLen];
			hkdf.generateBytes( output, 0, outLen );

			return output;
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 5 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "GenerateHKDFKey", 5, "outputLength",
					"Required arguments: algorithm, inputKeyMaterial, salt, info, outputLength", null );
		}

		String algorithm = cast.toString( args[0] );
		Object ikm = args[1];
		Object salt = args[2];
		Object info = args[3];
		Number outputLength = cast.toInteger( args[4] );

		return call( pc, algorithm, ikm, salt, info, outputLength );
	}
}
