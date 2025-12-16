package org.lucee.extension.crypto;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;

/**
 * Extracts information from an X.509 certificate.
 *
 * Usage:
 *   info = CertificateInfo( certPem )
 *   info = CertificateInfo( certObject )
 */
public class CertificateInfo extends BIF {

	private static final long serialVersionUID = 1L;

	public static Struct call( PageContext pc, Object certificate ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			X509Certificate cert;
			if ( certificate instanceof X509Certificate ) {
				cert = (X509Certificate) certificate;
			}
			else if ( certificate instanceof String ) {
				cert = CryptoUtil.parseCertificate( (String) certificate );
			}
			else {
				throw eng.getExceptionUtil().createApplicationException(
					"Certificate must be an X509Certificate object or PEM string"
				);
			}

			Struct result = eng.getCreationUtil().createStruct( Struct.TYPE_LINKED );

			// Basic info
			result.set( "subject", cert.getSubjectX500Principal().getName() );
			result.set( "issuer", cert.getIssuerX500Principal().getName() );
			result.set( "serialNumber", cert.getSerialNumber().toString() );

			// Validity
			result.set( "validFrom", eng.getCreationUtil().createDateTime( cert.getNotBefore().getTime() ) );
			result.set( "validTo", eng.getCreationUtil().createDateTime( cert.getNotAfter().getTime() ) );

			// Algorithms
			result.set( "algorithm", cert.getSigAlgName() );
			result.set( "publicKeyAlgorithm", cert.getPublicKey().getAlgorithm() );

			// Public key size (for RSA)
			if ( cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey ) {
				java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
				result.set( "publicKeySize", rsaKey.getModulus().bitLength() );
			}
			else if ( cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey ) {
				java.security.interfaces.ECPublicKey ecKey = (java.security.interfaces.ECPublicKey) cert.getPublicKey();
				result.set( "publicKeySize", ecKey.getParams().getOrder().bitLength() );
			}

			// Fingerprints
			Struct fingerprints = eng.getCreationUtil().createStruct();
			fingerprints.set( "sha1", getFingerprint( cert, "SHA-1" ) );
			fingerprints.set( "sha256", getFingerprint( cert, "SHA-256" ) );
			result.set( "fingerprint", fingerprints );

			// Version
			result.set( "version", cert.getVersion() );

			// Self-signed check
			result.set( "selfSigned", cert.getSubjectX500Principal().equals( cert.getIssuerX500Principal() ) );

			return result;
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static String getFingerprint( X509Certificate cert, String algorithm ) throws Exception {
		MessageDigest md = MessageDigest.getInstance( algorithm );
		byte[] digest = md.digest( cert.getEncoded() );
		StringBuilder sb = new StringBuilder();
		for ( int i = 0; i < digest.length; i++ ) {
			if ( i > 0 ) sb.append( ":" );
			sb.append( String.format( "%02X", digest[i] ) );
		}
		return sb.toString();
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "CertificateInfo", 1, "certificate", "Certificate is required", null );
		}

		return call( pc, args[0] );
	}
}
