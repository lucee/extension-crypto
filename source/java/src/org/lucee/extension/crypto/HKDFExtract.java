package org.lucee.extension.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Performs the Extract phase of HKDF to create a Pseudo-Random Key (PRK).
 *
 * Use this when you need to derive multiple keys from the same secret:
 *   1. Call HKDFExtract once to get the PRK
 *   2. Call HKDFExpand multiple times with different info to get derived keys
 *
 * Usage:
 *   prk = HKDFExtract( algorithm, salt, inputKeyMaterial )
 *   prk = HKDFExtract( "SHA256", saltBytes, secretBytes )
 *
 * Returns: binary (pseudo-random key)
 */
public class HKDFExtract extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String algorithm, Object salt, Object inputKeyMaterial ) throws PageException {
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

			// Create HKDF generator and extract PRK
			HKDFBytesGenerator hkdf = new HKDFBytesGenerator( digest );
			byte[] prk = hkdf.extractPRK( saltBytes, ikmBytes );

			return prk;
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 3 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "HKDFExtract", 3, "inputKeyMaterial",
					"Required arguments: algorithm, salt, inputKeyMaterial", null );
		}

		String algorithm = cast.toString( args[0] );
		Object salt = args[1];
		Object ikm = args[2];

		return call( pc, algorithm, salt, ikm );
	}
}
