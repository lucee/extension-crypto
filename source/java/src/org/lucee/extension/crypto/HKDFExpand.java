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
 * Performs the Expand phase of HKDF to derive key material from a PRK.
 *
 * Use this after HKDFExtract to derive multiple keys from the same PRK:
 *   prk = HKDFExtract( "SHA256", salt, ikm )
 *   key1 = HKDFExpand( "SHA256", prk, "encryption", 32 )
 *   key2 = HKDFExpand( "SHA256", prk, "authentication", 32 )
 *
 * Usage:
 *   key = HKDFExpand( algorithm, prk, info, outputLength )
 *
 * Returns: binary (derived key material)
 */
public class HKDFExpand extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String algorithm, Object prk,
							   Object info, Number outputLength ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Get digest
			Digest digest = CryptoUtil.getDigest( algorithm );
			if ( digest == null ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Unsupported algorithm: " + algorithm + ". Use SHA256, SHA384, or SHA512." );
			}

			// Convert PRK to bytes
			byte[] prkBytes = CryptoUtil.toBytesOrNull( prk );
			if ( prkBytes == null || prkBytes.length == 0 ) {
				throw eng.getExceptionUtil().createApplicationException( "PRK (pseudo-random key) is required" );
			}

			// Convert info to bytes (optional)
			byte[] infoBytes = CryptoUtil.toBytesOrNull( info );

			// Validate output length
			int outLen = outputLength != null ? outputLength.intValue() : 32;
			int maxLen = 255 * digest.getDigestSize();
			if ( outLen < 1 || outLen > maxLen ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Output length must be between 1 and " + maxLen + " bytes for " + algorithm );
			}

			// Create HKDF generator - use skipExtract since we already have the PRK
			HKDFBytesGenerator hkdf = new HKDFBytesGenerator( digest );
			hkdf.init( HKDFParameters.skipExtractParameters( prkBytes, infoBytes ) );

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

		if ( args.length < 4 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "HKDFExpand", 4, "outputLength",
					"Required arguments: algorithm, prk, info, outputLength", null );
		}

		String algorithm = cast.toString( args[0] );
		Object prk = args[1];
		Object info = args[2];
		Number outputLength = cast.toInteger( args[3] );

		return call( pc, algorithm, prk, info, outputLength );
	}
}
