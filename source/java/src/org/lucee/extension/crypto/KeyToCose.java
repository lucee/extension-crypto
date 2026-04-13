package org.lucee.extension.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

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
 * Converts a Java security key to a COSE key struct (integer keys per RFC 9052).
 *
 * Usage:
 *   coseKey = KeyToCose( publicKey )
 *   coseKey = KeyToCose( pemString )
 *   coseKey = KeyToCose( keyPairStruct )
 *
 * Returns struct with integer keys: 1 (kty), 3 (alg), -1 (crv), -2 (x), -3 (y), -4 (d)
 */
public class KeyToCose extends BIF {

	private static final long serialVersionUID = 1L;

	// COSE key type constants
	private static final int KTY_OKP = 1;
	private static final int KTY_EC2 = 2;

	// COSE algorithm constants
	private static final int ALG_ES256 = -7;
	private static final int ALG_ES384 = -35;
	private static final int ALG_ES512 = -36;
	private static final int ALG_EDDSA = -8;

	// COSE curve constants
	private static final int CRV_P256 = 1;
	private static final int CRV_P384 = 2;
	private static final int CRV_P521 = 3;
	private static final int CRV_ED25519 = 6;

	public static Object call( PageContext pc, Object key ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			// Handle PEM string
			if ( key instanceof String ) {
				String keyStr = (String) key;
				if ( keyStr.contains( "-----BEGIN" ) ) {
					Object parsed = CryptoUtil.parsePem( keyStr );
					return call( pc, parsed );
				}
				throw new IllegalArgumentException( "String key must be in PEM format (starts with -----BEGIN)" );
			}

			// Handle key pair struct from GenerateKeyPair()
			if ( eng.getDecisionUtil().isStruct( key ) ) {
				Struct kp = cast.toStruct( key );
				Object pubObj = kp.get( cast.toKey( "public" ), null );
				Object privObj = kp.get( cast.toKey( "private" ), null );

				PublicKey pubKey = null;
				PrivateKey privKey = null;

				if ( pubObj instanceof PublicKey ) {
					pubKey = (PublicKey) pubObj;
				}
				else if ( pubObj instanceof String ) {
					pubKey = CryptoUtil.parsePublicKey( (String) pubObj );
				}

				if ( privObj instanceof PrivateKey ) {
					privKey = (PrivateKey) privObj;
				}
				else if ( privObj instanceof String ) {
					privKey = CryptoUtil.parsePrivateKey( (String) privObj );
				}

				if ( pubKey != null ) {
					return buildCose( eng, pubKey, privKey );
				}
				if ( privKey != null ) {
					return buildCoseFromPrivate( eng, privKey );
				}
				throw new IllegalArgumentException( "Key pair struct must contain 'public' and/or 'private' key" );
			}

			// Handle Java key objects
			if ( key instanceof java.security.KeyPair ) {
				java.security.KeyPair kp = (java.security.KeyPair) key;
				return buildCose( eng, kp.getPublic(), kp.getPrivate() );
			}
			if ( key instanceof PublicKey ) {
				return buildCose( eng, (PublicKey) key, null );
			}
			if ( key instanceof PrivateKey ) {
				return buildCoseFromPrivate( eng, (PrivateKey) key );
			}

			throw new IllegalArgumentException(
				"Unsupported key type: " + key.getClass().getName() +
				". Expected: PublicKey, PrivateKey, PEM string, or key pair struct." );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static Struct buildCose( CFMLEngine eng, PublicKey pubKey, PrivateKey privKey ) throws Exception {
		Cast cast = eng.getCastUtil();
		Struct cose = eng.getCreationUtil().createStruct();

		if ( pubKey instanceof ECPublicKey ) {
			ECPublicKey ecPub = (ECPublicKey) pubKey;
			int fieldSize = ecPub.getParams().getCurve().getField().getFieldSize();
			int crv;
			int alg;
			int byteLen;

			if ( fieldSize <= 256 ) {
				crv = CRV_P256;
				alg = ALG_ES256;
				byteLen = 32;
			}
			else if ( fieldSize <= 384 ) {
				crv = CRV_P384;
				alg = ALG_ES384;
				byteLen = 48;
			}
			else {
				crv = CRV_P521;
				alg = ALG_ES512;
				byteLen = 66;
			}

			cose.set( cast.toKey( "1" ), KTY_EC2 );
			cose.set( cast.toKey( "3" ), alg );
			cose.set( cast.toKey( "-1" ), crv );
			cose.set( cast.toKey( "-2" ), toFixedBytes( ecPub.getW().getAffineX(), byteLen ) );
			cose.set( cast.toKey( "-3" ), toFixedBytes( ecPub.getW().getAffineY(), byteLen ) );

			// Include private key if provided
			if ( privKey instanceof ECPrivateKey ) {
				cose.set( cast.toKey( "-4" ), toFixedBytes( ( (ECPrivateKey) privKey ).getS(), byteLen ) );
			}

			return cose;
		}

		if ( pubKey instanceof EdDSAPublicKey ) {
			cose.set( cast.toKey( "1" ), KTY_OKP );
			cose.set( cast.toKey( "3" ), ALG_EDDSA );
			cose.set( cast.toKey( "-1" ), CRV_ED25519 );
			cose.set( cast.toKey( "-2" ), ( (EdDSAPublicKey) pubKey ).getPointEncoding() );

			if ( privKey instanceof EdDSAPrivateKey ) {
				org.bouncycastle.asn1.pkcs.PrivateKeyInfo info =
					org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance( privKey.getEncoded() );
				byte[] rawPriv = org.bouncycastle.asn1.ASN1OctetString.getInstance( info.parsePrivateKey() ).getOctets();
				cose.set( cast.toKey( "-4" ), rawPriv );
			}

			return cose;
		}

		throw new IllegalArgumentException( "Unsupported public key type: " + pubKey.getClass().getName() +
			". Supported: EC (P-256, P-384, P-521) and Ed25519." );
	}

	private static Struct buildCoseFromPrivate( CFMLEngine eng, PrivateKey privKey ) throws Exception {
		// For EdDSA, we can derive the public key
		if ( privKey instanceof EdDSAPrivateKey ) {
			EdDSAPublicKey pubKey = ( (EdDSAPrivateKey) privKey ).getPublicKey();
			return buildCose( eng, pubKey, privKey );
		}

		throw new IllegalArgumentException(
			"Cannot build COSE key from private key alone for key type: " + privKey.getAlgorithm() +
			". Pass a key pair struct with both 'private' and 'public' keys." );
	}

	/**
	 * Convert a BigInteger to a fixed-length byte array (big-endian, zero-padded).
	 * COSE requires fixed-length coordinate encoding.
	 */
	private static byte[] toFixedBytes( java.math.BigInteger value, int length ) {
		byte[] bytes = value.toByteArray();
		if ( bytes.length == length ) return bytes;

		byte[] result = new byte[length];
		if ( bytes.length > length ) {
			// Strip leading zero byte (sign bit)
			System.arraycopy( bytes, bytes.length - length, result, 0, length );
		}
		else {
			// Zero-pad on the left
			System.arraycopy( bytes, 0, result, length - bytes.length, bytes.length );
		}
		return result;
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "KeyToCose", 1, "key", "Key is required", null );
		}
		return call( pc, args[0] );
	}
}
