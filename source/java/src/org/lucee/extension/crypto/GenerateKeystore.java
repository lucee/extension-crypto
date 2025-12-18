package org.lucee.extension.crypto;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
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
import lucee.runtime.util.Cast;

/**
 * Generates a Java keystore with a key pair and self-signed certificate.
 *
 * Usage:
 *   GenerateKeystore(
 *       keystore = "/path/to/keystore.p12",
 *       keystorePassword = "changeit",
 *       alias = "mykey",
 *       algorithm = "RSA-2048",
 *       subject = "CN=localhost, O=MyOrg"
 *   )
 */
public class GenerateKeystore extends BIF {

	private static final long serialVersionUID = 1L;

	public static void call( PageContext pc, String keystorePath, String keystorePassword,
							 String alias, String algorithm, String subject, Struct options ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Defaults
			if ( algorithm == null || algorithm.trim().isEmpty() ) {
				algorithm = "RSA-2048";
			}
			else {
				algorithm = algorithm.trim();
			}
			if ( subject == null || subject.trim().isEmpty() ) {
				subject = "CN=localhost";
			}
			else {
				subject = subject.trim();
			}

			// Parse options
			Cast cast = eng.getCastUtil();
			String keystoreType = "PKCS12";
			String keyPassword = keystorePassword;
			int validityDays = 365;

			if ( options != null ) {
				Object typeObj = options.get( "keystoreType", null );
				if ( typeObj != null ) {
					keystoreType = cast.toString( typeObj ).trim().toUpperCase();
				}
				Object keyPassObj = options.get( "keyPassword", null );
				if ( keyPassObj != null ) {
					keyPassword = cast.toString( keyPassObj );
				}
				Object daysObj = options.get( "validityDays", null );
				if ( daysObj != null ) {
					validityDays = cast.toIntValue( daysObj );
				}
			}

			// Auto-detect type from extension if not specified
			if ( options == null || options.get( "keystoreType", null ) == null ) {
				if ( keystorePath.toLowerCase().endsWith( ".jks" ) ) {
					keystoreType = "JKS";
				}
			}

			// Generate key pair
			KeyPair keyPair = CryptoUtil.generateKeyPair( algorithm );
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();

			// Generate self-signed certificate
			X509Certificate cert = generateCertificate( privateKey, publicKey, subject, validityDays );

			// Create and populate keystore
			KeyStore ks = KeyStore.getInstance( keystoreType );
			ks.load( null, keystorePassword.toCharArray() );

			ks.setKeyEntry( alias, privateKey, keyPassword.toCharArray(), new Certificate[] { cert } );

			// Write to file
			try ( FileOutputStream fos = new FileOutputStream( keystorePath ) ) {
				ks.store( fos, keystorePassword.toCharArray() );
			}
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static X509Certificate generateCertificate( PrivateKey privateKey, PublicKey publicKey,
														String subject, int validityDays ) throws Exception {
		X500Name x500Name = new X500Name( subject );
		BigInteger serial = BigInteger.valueOf( System.currentTimeMillis() );
		Date notBefore = new Date();
		Date notAfter = new Date( notBefore.getTime() + ( validityDays * 86400000L ) );

		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			x500Name, serial, notBefore, notAfter, x500Name, publicKey
		);

		String sigAlg = CryptoUtil.getSignatureAlgorithm( privateKey );
		ContentSigner signer = new JcaContentSignerBuilder( sigAlg )
			.setProvider( "BC" )
			.build( privateKey );

		return new JcaX509CertificateConverter()
			.setProvider( "BC" )
			.getCertificate( builder.build( signer ) );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 3 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "GenerateKeystore", 3, "alias",
				"keystore, keystorePassword, and alias are required", null
			);
		}

		String keystorePath = cast.toString( args[0] );
		String keystorePassword = cast.toString( args[1] );
		String alias = cast.toString( args[2] );
		String algorithm = args.length > 3 && args[3] != null ? cast.toString( args[3] ) : null;
		String subject = args.length > 4 && args[4] != null ? cast.toString( args[4] ) : null;
		Struct options = args.length > 5 && args[5] != null ? cast.toStruct( args[5] ) : null;

		call( pc, keystorePath, keystorePassword, alias, algorithm, subject, options );
		return null;
	}
}
