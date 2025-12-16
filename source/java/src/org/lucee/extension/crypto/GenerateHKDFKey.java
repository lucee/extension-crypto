package org.lucee.extension.crypto;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

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
			Digest digest = getDigest( algorithm );
			if ( digest == null ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Unsupported algorithm: " + algorithm + ". Use SHA256, SHA384, or SHA512." );
			}

			// Convert IKM to bytes
			byte[] ikmBytes = toBytes( eng, inputKeyMaterial );
			if ( ikmBytes == null || ikmBytes.length == 0 ) {
				throw eng.getExceptionUtil().createApplicationException( "Input key material is required" );
			}

			// Convert salt to bytes (optional)
			byte[] saltBytes = toBytes( eng, salt );

			// Convert info to bytes (optional)
			byte[] infoBytes = toBytes( eng, info );

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
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static Digest getDigest( String algorithm ) {
		if ( algorithm == null || algorithm.trim().isEmpty() ) return new SHA256Digest();

		switch ( algorithm.trim().toUpperCase().replace( "-", "" ) ) {
			case "SHA256":
			case "SHA2256":
				return new SHA256Digest();
			case "SHA384":
			case "SHA2384":
				return new SHA384Digest();
			case "SHA512":
			case "SHA2512":
				return new SHA512Digest();
			default:
				return null;
		}
	}

	private static byte[] toBytes( CFMLEngine eng, Object obj ) throws PageException {
		if ( obj == null ) return null;
		if ( obj instanceof byte[] ) return (byte[]) obj;
		String str = eng.getCastUtil().toString( obj );
		if ( str.isEmpty() ) return null;
		return str.getBytes( StandardCharsets.UTF_8 );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 5 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "GenerateHKDFKey", 5, "outputLength",
					"Required arguments: algorithm, inputKeyMaterial, salt, info, outputLength", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String algorithm = eng.getCastUtil().toString( args[0] );
		Object ikm = args[1];
		Object salt = args[2];
		Object info = args[3];
		Number outputLength = eng.getCastUtil().toInteger( args[4] );

		return call( pc, algorithm, ikm, salt, info, outputLength );
	}
}
