package org.lucee.extension.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Converts a Java key object or PEM string to a JWK (JSON Web Key) struct.
 *
 * Usage:
 *   jwk = KeyToJwk( publicKey )
 *   jwk = KeyToJwk( pemString )
 *   jwk = KeyToJwk( keyPairStruct )   // includes private key material
 *
 * Supports RSA, EC (P-256, P-384, P-521), and Ed25519 keys.
 * Follows the KeyToPem/PemToKey naming pattern.
 */
public class KeyToJwk extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, Object key ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			JWK jwk = null;

			// Handle PEM string
			if ( key instanceof String ) {
				String keyStr = (String) key;
				if ( keyStr.contains( "-----BEGIN" ) ) {
					Object parsed = CryptoUtil.parsePem( keyStr );
					return call( pc, parsed );
				}
				throw new IllegalArgumentException( "String key must be in PEM format (starts with -----BEGIN)" );
			}

			// Handle Struct (key pair from GenerateKeyPair)
			if ( eng.getDecisionUtil().isStruct( key ) ) {
				Struct kp = cast.toStruct( key );
				Object privObj = kp.get( cast.toKey( "private" ), null );
				Object pubObj = kp.get( cast.toKey( "public" ), null );

				// Parse PEM strings if needed
				PrivateKey privKey = null;
				PublicKey pubKey = null;

				if ( privObj instanceof PrivateKey ) {
					privKey = (PrivateKey) privObj;
				}
				else if ( privObj instanceof String ) {
					privKey = CryptoUtil.parsePrivateKey( (String) privObj );
				}

				if ( pubObj instanceof PublicKey ) {
					pubKey = (PublicKey) pubObj;
				}
				else if ( pubObj instanceof String ) {
					pubKey = CryptoUtil.parsePublicKey( (String) pubObj );
				}

				jwk = toJwk( pubKey, privKey );
			}
			// Handle Java key objects directly
			else if ( key instanceof PublicKey ) {
				jwk = toJwk( (PublicKey) key, null );
			}
			else if ( key instanceof PrivateKey ) {
				jwk = toJwkFromPrivate( (PrivateKey) key );
			}
			else if ( key instanceof SecretKey ) {
				jwk = new OctetSequenceKey.Builder( (SecretKey) key ).build();
			}
			else {
				throw new IllegalArgumentException(
					"Unsupported key type: " + key.getClass().getName() +
					". Expected: PublicKey, PrivateKey, SecretKey, PEM string, or key pair struct." );
			}

			// Convert JWK JSON map to CFML struct
			return CryptoUtil.mapToStruct( eng, jwk.toJSONObject() );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static JWK toJwk( PublicKey pubKey, PrivateKey privKey ) throws Exception {
		if ( pubKey instanceof RSAPublicKey ) {
			RSAKey.Builder builder = new RSAKey.Builder( (RSAPublicKey) pubKey );
			if ( privKey instanceof RSAPrivateKey ) {
				builder.privateKey( (RSAPrivateKey) privKey );
			}
			return builder.build();
		}

		if ( pubKey instanceof ECPublicKey ) {
			Curve curve = Curve.forECParameterSpec( ( (ECPublicKey) pubKey ).getParams() );
			ECKey.Builder builder = new ECKey.Builder( curve, (ECPublicKey) pubKey );
			if ( privKey instanceof ECPrivateKey ) {
				builder.privateKey( (ECPrivateKey) privKey );
			}
			return builder.build();
		}

		// EdDSA (BouncyCastle)
		if ( pubKey instanceof EdDSAPublicKey ) {
			OctetKeyPair.Builder builder = new OctetKeyPair.Builder(
				Curve.Ed25519,
				com.nimbusds.jose.util.Base64URL.encode( getEdPublicKeyBytes( pubKey ) )
			);
			if ( privKey instanceof EdDSAPrivateKey ) {
				builder.d( com.nimbusds.jose.util.Base64URL.encode( getEdPrivateKeyBytes( privKey ) ) );
			}
			return builder.build();
		}

		throw new IllegalArgumentException( "Unsupported public key type: " + pubKey.getClass().getName() );
	}

	private static JWK toJwkFromPrivate( PrivateKey privKey ) throws Exception {
		// For RSA/EC, we can build a JWK with just the private key (no public component)
		// but that's unusual. For EdDSA we can extract the public key.
		if ( privKey instanceof RSAPrivateKey ) {
			// RSA private-only JWK isn't standard, need the public component
			throw new IllegalArgumentException(
				"RSA private key alone cannot produce a valid JWK. Pass a key pair struct with both 'private' and 'public' keys." );
		}
		if ( privKey instanceof ECPrivateKey ) {
			throw new IllegalArgumentException(
				"EC private key alone cannot produce a valid JWK. Pass a key pair struct with both 'private' and 'public' keys." );
		}
		if ( privKey instanceof EdDSAPrivateKey ) {
			// BC EdDSA private keys can derive the public key
			EdDSAPublicKey pubKey = ( (EdDSAPrivateKey) privKey ).getPublicKey();
			return toJwk( pubKey, privKey );
		}

		throw new IllegalArgumentException( "Unsupported private key type: " + privKey.getClass().getName() );
	}

	/**
	 * Extract raw public key bytes from an EdDSA public key using the BC interface.
	 */
	private static byte[] getEdPublicKeyBytes( PublicKey key ) {
		return ( (EdDSAPublicKey) key ).getPointEncoding();
	}

	/**
	 * Extract raw private key bytes from an EdDSA private key via ASN.1 parsing.
	 */
	private static byte[] getEdPrivateKeyBytes( PrivateKey key ) throws Exception {
		org.bouncycastle.asn1.pkcs.PrivateKeyInfo info =
			org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance( key.getEncoded() );
		// The private key is wrapped in an OCTET STRING inside another OCTET STRING
		return org.bouncycastle.asn1.ASN1OctetString.getInstance( info.parsePrivateKey() ).getOctets();
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "KeyToJwk", 1, "key", "Key is required", null );
		}

		return call( pc, args[0] );
	}
}
