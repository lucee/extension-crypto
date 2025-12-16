package org.lucee.extension.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;

/**
 * Generates a self-signed X.509 certificate.
 *
 * Usage:
 *   cert = GenerateSelfSignedCertificate( privateKey=privPem, publicKey=pubPem, subject="CN=localhost", validityDays=365 )
 *   cert = GenerateSelfSignedCertificate( keyPair=keyPairStruct, subject="CN=localhost" )
 */
public class GenerateSelfSignedCertificate extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object privateKey, Object publicKey, Struct keyPair,
							   String subject, Number validityDays, String algorithm ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			PrivateKey privKey = null;
			PublicKey pubKey = null;

			// Get keys from keyPair struct if provided
			if ( keyPair != null ) {
				Object privObj = keyPair.get( "private", null );
				Object pubObj = keyPair.get( "public", null );

				if ( privObj != null ) {
					privKey = extractPrivateKey( privObj );
				}
				if ( pubObj != null ) {
					pubKey = extractPublicKey( pubObj );
				}
			}

			// Override with individual key params if provided
			if ( privateKey != null ) {
				privKey = extractPrivateKey( privateKey );
			}
			if ( publicKey != null ) {
				pubKey = extractPublicKey( publicKey );
			}

			if ( privKey == null || pubKey == null ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Both privateKey and publicKey are required (either individually or via keyPair struct)"
				);
			}

			// Defaults
			int days = validityDays != null ? validityDays.intValue() : 365;
			String sigAlg = algorithm;
			if ( sigAlg == null || sigAlg.trim().isEmpty() ) {
				sigAlg = CryptoUtil.getSignatureAlgorithm( privKey );
			}
			else {
				sigAlg = sigAlg.trim();
			}

			// Build certificate
			X500Name x500Name = new X500Name( subject );
			BigInteger serial = BigInteger.valueOf( System.currentTimeMillis() );
			Date notBefore = new Date();
			Date notAfter = new Date( notBefore.getTime() + ( days * 86400000L ) );

			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				x500Name,   // issuer
				serial,     // serial
				notBefore,  // not before
				notAfter,   // not after
				x500Name,   // subject (same as issuer for self-signed)
				pubKey      // public key
			);

			ContentSigner signer = new JcaContentSignerBuilder( sigAlg )
				.setProvider( "BC" )
				.build( privKey );

			X509Certificate cert = new JcaX509CertificateConverter()
				.setProvider( "BC" )
				.getCertificate( builder.build( signer ) );

			return CryptoUtil.toPem( cert );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static PrivateKey extractPrivateKey( Object key ) throws Exception {
		if ( key instanceof PrivateKey ) {
			return (PrivateKey) key;
		}
		if ( key instanceof String ) {
			return CryptoUtil.parsePrivateKey( (String) key );
		}
		throw new IllegalArgumentException( "Cannot extract PrivateKey from: " + key.getClass().getName() );
	}

	private static PublicKey extractPublicKey( Object key ) throws Exception {
		if ( key instanceof PublicKey ) {
			return (PublicKey) key;
		}
		if ( key instanceof String ) {
			return CryptoUtil.parsePublicKey( (String) key );
		}
		throw new IllegalArgumentException( "Cannot extract PublicKey from: " + key.getClass().getName() );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		// Named parameters handling - this is a complex function
		// For simplicity, we'll support positional: privateKey, publicKey, keyPair, subject, validityDays, algorithm
		Object privateKey = args.length > 0 && !eng.getDecisionUtil().isEmpty( args[0] ) ? args[0] : null;
		Object publicKey = args.length > 1 && !eng.getDecisionUtil().isEmpty( args[1] ) ? args[1] : null;
		Struct keyPair = null;
		if ( args.length > 2 && args[2] != null ) {
			Struct s = eng.getCastUtil().toStruct( args[2], null );
			if ( s != null && s.size() > 0 ) {
				keyPair = s;
			}
		}
		String subject = args.length > 3 ? eng.getCastUtil().toString( args[3] ) : null;
		Number validityDays = args.length > 4 && args[4] != null ? eng.getCastUtil().toInteger( args[4] ) : 365;
		String algorithm = args.length > 5 && args[5] != null ? eng.getCastUtil().toString( args[5] ) : null;

		if ( subject == null || subject.isEmpty() ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "GenerateSelfSignedCertificate", 4, "subject", "Subject is required", null
			);
		}

		return call( pc, privateKey, publicKey, keyPair, subject, validityDays, algorithm );
	}
}
