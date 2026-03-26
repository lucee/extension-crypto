package org.lucee.extension.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Converts a JWK (JSON Web Key) struct or JSON string to a Java key object.
 *
 * Usage:
 *   key = JwkToKey( jwkStruct )     // returns PublicKey, PrivateKey, or SecretKey
 *   key = JwkToKey( jwkJsonString )
 *
 * If the JWK contains private key material (d parameter), returns a PrivateKey.
 * Otherwise returns a PublicKey. For symmetric keys (kty=oct), returns a SecretKey.
 *
 * Follows the KeyToPem/PemToKey naming pattern.
 */
public class JwkToKey extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, Object jwkInput ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			JWK jwk;

			if ( jwkInput instanceof String ) {
				jwk = JWK.parse( (String) jwkInput );
			}
			else if ( eng.getDecisionUtil().isStruct( jwkInput ) ) {
				// Convert CFML struct to JSON string via Lucee's serializer, then parse
				Struct s = cast.toStruct( jwkInput );
				String json = cast.fromStructToJsonString( s, true );
				jwk = JWK.parse( json );
			}
			else {
				throw new IllegalArgumentException(
					"Expected a JWK struct or JSON string, got: " + jwkInput.getClass().getName() );
			}

			return extractKey( jwk );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static Object extractKey( JWK jwk ) throws JOSEException {
		// RSA
		if ( jwk instanceof RSAKey ) {
			RSAKey rsaKey = (RSAKey) jwk;
			if ( rsaKey.isPrivate() ) {
				return rsaKey.toRSAPrivateKey();
			}
			return rsaKey.toRSAPublicKey();
		}

		// EC
		if ( jwk instanceof ECKey ) {
			ECKey ecKey = (ECKey) jwk;
			if ( ecKey.isPrivate() ) {
				return ecKey.toECPrivateKey();
			}
			return ecKey.toECPublicKey();
		}

		// EdDSA (OKP)
		if ( jwk instanceof OctetKeyPair ) {
			OctetKeyPair okp = (OctetKeyPair) jwk;
			// Nimbus OctetKeyPair doesn't directly produce Java keys,
			// so we reconstruct via BouncyCastle from the raw bytes
			if ( okp.isPrivate() ) {
				return edPrivateKeyFromBytes( okp.getDecodedD(), okp.getDecodedX() );
			}
			return edPublicKeyFromBytes( okp.getDecodedX() );
		}

		// Symmetric (oct)
		if ( jwk instanceof OctetSequenceKey ) {
			return ( (OctetSequenceKey) jwk ).toSecretKey();
		}

		throw new IllegalArgumentException( "Unsupported JWK key type: " + jwk.getKeyType() );
	}

	/**
	 * Reconstruct an Ed25519 public key from raw bytes via BouncyCastle.
	 */
	private static PublicKey edPublicKeyFromBytes( byte[] publicKeyBytes ) throws JOSEException {
		try {
			org.bouncycastle.asn1.x509.SubjectPublicKeyInfo info =
				new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
					new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
						org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_Ed25519 ),
					publicKeyBytes
				);
			java.security.KeyFactory kf = java.security.KeyFactory.getInstance( "Ed25519", "BC" );
			return kf.generatePublic( new java.security.spec.X509EncodedKeySpec( info.getEncoded() ) );
		}
		catch ( Exception e ) {
			throw new JOSEException( "Failed to reconstruct Ed25519 public key: " + e.getMessage(), e );
		}
	}

	/**
	 * Reconstruct an Ed25519 private key from raw bytes via BouncyCastle.
	 */
	private static PrivateKey edPrivateKeyFromBytes( byte[] privateKeyBytes, byte[] publicKeyBytes ) throws JOSEException {
		try {
			org.bouncycastle.asn1.pkcs.PrivateKeyInfo info =
				new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(
					new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
						org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_Ed25519 ),
					new org.bouncycastle.asn1.DEROctetString( privateKeyBytes )
				);
			java.security.KeyFactory kf = java.security.KeyFactory.getInstance( "Ed25519", "BC" );
			return kf.generatePrivate( new java.security.spec.PKCS8EncodedKeySpec( info.getEncoded() ) );
		}
		catch ( Exception e ) {
			throw new JOSEException( "Failed to reconstruct Ed25519 private key: " + e.getMessage(), e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "JwkToKey", 1, "jwk", "JWK is required", null );
		}

		return call( pc, args[0] );
	}
}
