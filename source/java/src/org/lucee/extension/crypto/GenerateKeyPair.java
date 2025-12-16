package org.lucee.extension.crypto;

import java.security.KeyPair;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;

/**
 * Generates a cryptographic key pair for the specified algorithm.
 *
 * Usage:
 *   keyPair = GenerateKeyPair( "RSA-2048" )
 *   keyPair = GenerateKeyPair( "P-256" )
 *   keyPair = GenerateKeyPair( "Ed25519" )
 *
 * Returns struct with 'private' and 'public' keys in PEM format.
 */
public class GenerateKeyPair extends BIF {

	private static final long serialVersionUID = 1L;

	public static Struct call( PageContext pc, String algorithm ) throws PageException {
		return call( pc, algorithm, null );
	}

	public static Struct call( PageContext pc, String algorithm, Struct options ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Trim algorithm
			algorithm = algorithm.trim();

			// Parse options
			String format = "PEM";
			if ( options != null ) {
				Object formatObj = options.get( "format", null );
				if ( formatObj != null ) {
					format = eng.getCastUtil().toString( formatObj ).trim().toUpperCase();
				}
			}

			// Generate key pair
			KeyPair keyPair = CryptoUtil.generateKeyPair( algorithm );

			// Create result struct
			Struct result = eng.getCreationUtil().createStruct();

			switch ( format ) {
				case "PEM":
				case "PKCS8":
					// PKCS#8 format (algorithm-agnostic, modern standard)
					result.set( "private", CryptoUtil.toPemPKCS8( keyPair.getPrivate() ) );
					result.set( "public", CryptoUtil.toPem( keyPair.getPublic() ) );
					break;

				case "TRADITIONAL":
				case "OPENSSL":
					// Traditional format (algorithm-specific: RSA PRIVATE KEY, EC PRIVATE KEY)
					// Not all algorithms support this format
					String algoUpper = algorithm.toUpperCase();
					if ( algoUpper.startsWith( "ED" ) || algoUpper.contains( "25519" ) || algoUpper.contains( "448" ) ) {
						throw eng.getExceptionUtil().createApplicationException(
							"Algorithm '" + algorithm + "' does not support traditional PEM format. Use 'PEM' or 'PKCS8' instead." );
					}
					result.set( "private", CryptoUtil.toPemTraditional( keyPair.getPrivate() ) );
					result.set( "public", CryptoUtil.toPem( keyPair.getPublic() ) );
					break;

				case "DER":
					result.set( "private", keyPair.getPrivate().getEncoded() );
					result.set( "public", keyPair.getPublic().getEncoded() );
					break;

				case "BASE64":
					result.set( "private", java.util.Base64.getEncoder().encodeToString( keyPair.getPrivate().getEncoded() ) );
					result.set( "public", java.util.Base64.getEncoder().encodeToString( keyPair.getPublic().getEncoded() ) );
					break;

				default:
					throw eng.getExceptionUtil().createApplicationException(
						"Unknown format: " + format + ". Use PEM, PKCS8, traditional, DER, or Base64." );
			}

			return result;

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
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "GenerateKeyPair", 1, "algorithm", "Algorithm is required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String algorithm = eng.getCastUtil().toString( args[0] );
		Struct options = args.length > 1 && args[1] != null ? eng.getCastUtil().toStruct( args[1] ) : null;

		return call( pc, algorithm, options );
	}
}
