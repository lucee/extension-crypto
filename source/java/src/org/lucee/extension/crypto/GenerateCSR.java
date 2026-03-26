package org.lucee.extension.crypto;

import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Array;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Generates a PKCS#10 Certificate Signing Request (CSR).
 *
 * Usage:
 *   csr = GenerateCSR( keyPair, "CN=example.com,O=My Org,C=AU" )
 *   csr = GenerateCSR( keyPair, "CN=example.com", { sans: ["example.com", "www.example.com"], algorithm: "SHA256withRSA" } )
 *
 * The first argument is a key pair struct (from GenerateKeyPair) containing both
 * 'private' and 'public' keys, since a CSR embeds the public key.
 *
 * Returns a PEM-encoded CSR string suitable for submission to a Certificate Authority.
 * The signature algorithm is auto-detected from the key type unless explicitly specified.
 *
 * Completes the certificate lifecycle: GenerateKeyPair -> GenerateCSR -> (submit to CA) -> (receive cert).
 */
public class GenerateCSR extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object keyPair, String subject ) throws PageException {
		return call( pc, keyPair, subject, null );
	}

	public static String call( PageContext pc, Object keyPair, String subject, Struct options ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			// Parse key pair — need both private (for signing) and public (embedded in CSR)
			PrivateKey privKey;
			PublicKey pubKey;

			if ( eng.getDecisionUtil().isStruct( keyPair ) ) {
				Struct kp = cast.toStruct( keyPair );
				Object privObj = kp.get( cast.toKey( "private" ), null );
				Object pubObj = kp.get( cast.toKey( "public" ), null );

				if ( privObj == null || pubObj == null ) {
					throw new IllegalArgumentException(
						"Key pair struct must contain both 'private' and 'public' keys" );
				}

				privKey = privObj instanceof PrivateKey ? (PrivateKey) privObj
					: CryptoUtil.parsePrivateKey( cast.toString( privObj ) );
				pubKey = pubObj instanceof PublicKey ? (PublicKey) pubObj
					: CryptoUtil.parsePublicKey( cast.toString( pubObj ) );
			}
			else {
				throw new IllegalArgumentException(
					"First argument must be a key pair struct (from GenerateKeyPair) with 'private' and 'public' keys" );
			}

			// Parse options
			String algorithm = null;
			String[] sans = null;

			if ( options != null ) {
				Object algVal = options.get( cast.toKey( "algorithm" ), null );
				if ( algVal != null ) algorithm = cast.toString( algVal );

				Object sansVal = options.get( cast.toKey( "sans" ), null );
				if ( sansVal != null ) {
					if ( eng.getDecisionUtil().isArray( sansVal ) ) {
						Array sansArr = cast.toArray( sansVal );
						sans = new String[sansArr.size()];
						for ( int i = 1; i <= sansArr.size(); i++ ) {
							sans[i - 1] = cast.toString( sansArr.getE( i ) );
						}
					}
				}
			}

			// Auto-detect signature algorithm from key type
			String sigAlg = algorithm;
			if ( sigAlg == null || sigAlg.trim().isEmpty() ) {
				sigAlg = CryptoUtil.getSignatureAlgorithm( privKey );
			}

			// Build CSR
			X500Principal principal = new X500Principal( subject );
			PKCS10CertificationRequestBuilder csrBuilder =
				new JcaPKCS10CertificationRequestBuilder( principal, pubKey );

			// Add SANs if provided
			if ( sans != null && sans.length > 0 ) {
				GeneralName[] names = new GeneralName[sans.length];
				for ( int i = 0; i < sans.length; i++ ) {
					names[i] = new GeneralName( GeneralName.dNSName, sans[i] );
				}
				ExtensionsGenerator extGen = new ExtensionsGenerator();
				extGen.addExtension( Extension.subjectAlternativeName, false, new GeneralNames( names ) );
				csrBuilder.addAttribute(
					org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
					extGen.generate()
				);
			}

			// Sign CSR
			ContentSigner signer = new JcaContentSignerBuilder( sigAlg )
				.setProvider( "BC" )
				.build( privKey );

			PKCS10CertificationRequest csr = csrBuilder.build( signer );

			// Convert to PEM
			StringWriter sw = new StringWriter();
			try ( JcaPEMWriter pw = new JcaPEMWriter( sw ) ) {
				pw.writeObject( csr );
			}
			return sw.toString().trim();
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

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "GenerateCSR", 2, "subject", "privateKey and subject are required", null );
		}

		Object privateKey = args[0];
		String subject = cast.toString( args[1] );
		Struct options = args.length > 2 && args[2] != null ? cast.toStruct( args[2] ) : null;

		return call( pc, privateKey, subject, options );
	}
}
