package org.lucee.extension.crypto;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Converts a COSE key (struct with integer keys per RFC 9052) to a Java security key.
 *
 * Usage:
 *   publicKey = CoseToKey( coseKeyStruct )
 *   publicKey = CoseToKey( coseKeyBytes )   // raw CBOR decoded internally
 *
 * COSE key integer fields:
 *   1 = kty (2=EC, 1=OKP)
 *   3 = alg (-7=ES256, -35=ES384, -36=ES512, -8=EdDSA)
 *  -1 = crv (1=P-256, 2=P-384, 3=P-521, 6=Ed25519)
 *  -2 = x coordinate (binary)
 *  -3 = y coordinate (binary, EC only)
 *  -4 = d private key (binary, optional)
 */
public class CoseToKey extends BIF {

	private static final long serialVersionUID = 1L;

	// COSE key type constants
	private static final int KTY_OKP = 1;
	private static final int KTY_EC2 = 2;

	// COSE curve constants
	private static final int CRV_P256 = 1;
	private static final int CRV_P384 = 2;
	private static final int CRV_P521 = 3;
	private static final int CRV_ED25519 = 6;

	public static Object call( PageContext pc, Object coseKey ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			Struct cose;

			// If binary, decode CBOR first
			if ( eng.getDecisionUtil().isBinary( coseKey ) ) {
				byte[] bytes = cast.toBinary( coseKey );
				Object decoded = CborDecode.call( pc, bytes, null );
				if ( !eng.getDecisionUtil().isStruct( decoded ) ) {
					throw new IllegalArgumentException( "CBOR-decoded COSE key must be a map/struct" );
				}
				cose = cast.toStruct( decoded );
			}
			else if ( eng.getDecisionUtil().isStruct( coseKey ) ) {
				cose = cast.toStruct( coseKey );
			}
			else {
				throw new IllegalArgumentException(
					"CoseToKey requires a struct (COSE key map) or binary (CBOR-encoded COSE key)" );
			}

			int kty = getIntField( cast, cose, "1" );
			int crv = getIntField( cast, cose, "-1" );
			byte[] x = getBinaryField( cast, cose, eng, "-2" );

			switch ( kty ) {
				case KTY_EC2:
					return buildEcKey( cast, eng, cose, crv, x );
				case KTY_OKP:
					return buildOkpKey( cast, eng, cose, crv, x );
				default:
					throw new IllegalArgumentException( "Unsupported COSE key type (kty): " + kty +
						". Supported: 2 (EC), 1 (OKP/EdDSA)" );
			}
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static Object buildEcKey( Cast cast, CFMLEngine eng, Struct cose, int crv, byte[] x ) throws Exception {
		byte[] y = getBinaryField( cast, cose, eng, "-3" );
		byte[] d = getBinaryFieldOrNull( cast, cose, eng, "-4" );

		String curveName;
		switch ( crv ) {
			case CRV_P256:
				curveName = "P-256";
				break;
			case CRV_P384:
				curveName = "P-384";
				break;
			case CRV_P521:
				curveName = "P-521";
				break;
			default:
				throw new IllegalArgumentException( "Unsupported EC curve (crv): " + crv +
					". Supported: 1 (P-256), 2 (P-384), 3 (P-521)" );
		}

		ECParameterSpec ecSpec = getEcParameterSpec( curveName );
		KeyFactory kf = KeyFactory.getInstance( "EC", "BC" );

		// Always build public key
		BigInteger xInt = new BigInteger( 1, x );
		BigInteger yInt = new BigInteger( 1, y );
		ECPoint point = new ECPoint( xInt, yInt );
		ECPublicKeySpec pubSpec = new ECPublicKeySpec( point, ecSpec );
		Key pubKey = kf.generatePublic( pubSpec );

		// If d is present, also build private key and return key pair struct
		if ( d != null ) {
			BigInteger dInt = new BigInteger( 1, d );
			ECPrivateKeySpec privSpec = new ECPrivateKeySpec( dInt, ecSpec );
			Key privKey = kf.generatePrivate( privSpec );
			return createKeyStruct( eng, pubKey, privKey );
		}

		return createKeyStruct( eng, pubKey, null );
	}

	private static Object buildOkpKey( Cast cast, CFMLEngine eng, Struct cose, int crv, byte[] x ) throws Exception {
		byte[] d = getBinaryFieldOrNull( cast, cose, eng, "-4" );

		if ( crv != CRV_ED25519 ) {
			throw new IllegalArgumentException( "Unsupported OKP curve (crv): " + crv +
				". Supported: 6 (Ed25519)" );
		}

		KeyFactory kf = KeyFactory.getInstance( "Ed25519", "BC" );

		// Always build public key from raw x coordinate
		byte[] x509 = wrapEd25519PublicKey( x );
		Key pubKey = kf.generatePublic( new java.security.spec.X509EncodedKeySpec( x509 ) );

		// If d is present, also build private key and return key pair struct
		if ( d != null ) {
			byte[] pkcs8 = wrapEd25519PrivateKey( d );
			Key privKey = kf.generatePrivate( new java.security.spec.PKCS8EncodedKeySpec( pkcs8 ) );
			return createKeyStruct( eng, pubKey, privKey );
		}

		return createKeyStruct( eng, pubKey, null );
	}

	/**
	 * Create a key struct with 'public' and optionally 'private' key, matching GenerateKeyPair output.
	 */
	private static Struct createKeyStruct( CFMLEngine eng, Key pubKey, Key privKey ) throws PageException {
		Cast cast = eng.getCastUtil();
		Struct kp = eng.getCreationUtil().createStruct();
		kp.set( cast.toKey( "public" ), pubKey );
		if ( privKey != null ) {
			kp.set( cast.toKey( "private" ), privKey );
		}
		return kp;
	}

	/**
	 * Wrap raw Ed25519 public key bytes in X.509 SubjectPublicKeyInfo ASN.1 structure.
	 */
	private static byte[] wrapEd25519PublicKey( byte[] rawKey ) {
		// Ed25519 OID: 1.3.101.112
		byte[] prefix = new byte[] {
			0x30, 0x2a, // SEQUENCE (42 bytes)
			0x30, 0x05, // SEQUENCE (5 bytes) - AlgorithmIdentifier
			0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
			0x03, 0x21, 0x00 // BIT STRING (33 bytes, 0 unused bits)
		};
		byte[] result = new byte[prefix.length + rawKey.length];
		System.arraycopy( prefix, 0, result, 0, prefix.length );
		System.arraycopy( rawKey, 0, result, prefix.length, rawKey.length );
		return result;
	}

	/**
	 * Wrap raw Ed25519 private key bytes in PKCS#8 ASN.1 structure.
	 */
	private static byte[] wrapEd25519PrivateKey( byte[] rawKey ) {
		// PKCS#8 wrapping for Ed25519: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { OCTET STRING { key } } }
		byte[] innerOctet = new byte[2 + rawKey.length];
		innerOctet[0] = 0x04; // OCTET STRING tag
		innerOctet[1] = (byte) rawKey.length;
		System.arraycopy( rawKey, 0, innerOctet, 2, rawKey.length );

		byte[] prefix = new byte[] {
			0x30, (byte) ( 3 + 7 + 2 + innerOctet.length ), // SEQUENCE
			0x02, 0x01, 0x00, // INTEGER version = 0
			0x30, 0x05, // SEQUENCE - AlgorithmIdentifier
			0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
			0x04, (byte) innerOctet.length // OCTET STRING wrapper
		};
		byte[] result = new byte[prefix.length + innerOctet.length];
		System.arraycopy( prefix, 0, result, 0, prefix.length );
		System.arraycopy( innerOctet, 0, result, prefix.length, innerOctet.length );
		return result;
	}

	private static ECParameterSpec getEcParameterSpec( String curveName ) throws Exception {
		String jceName;
		switch ( curveName ) {
			case "P-256":
				jceName = "secp256r1";
				break;
			case "P-384":
				jceName = "secp384r1";
				break;
			case "P-521":
				jceName = "secp521r1";
				break;
			default:
				jceName = curveName;
		}
		// Use BouncyCastle's named curve to get proper ECParameterSpec
		ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec( jceName );
		return new ECNamedCurveSpec(
			jceName,
			bcSpec.getCurve(),
			bcSpec.getG(),
			bcSpec.getN(),
			bcSpec.getH()
		);
	}

	private static int getIntField( Cast cast, Struct cose, String key ) throws PageException {
		Object val = cose.get( cast.toKey( key ), null );
		if ( val == null ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createApplicationException( "COSE key missing required field: " + key );
		}
		return cast.toIntValue( val );
	}

	private static byte[] getBinaryField( Cast cast, Struct cose, CFMLEngine eng, String key ) throws PageException {
		Object val = cose.get( cast.toKey( key ), null );
		if ( val == null ) {
			throw eng.getExceptionUtil()
				.createApplicationException( "COSE key missing required field: " + key );
		}
		if ( eng.getDecisionUtil().isBinary( val ) ) {
			return cast.toBinary( val );
		}
		throw eng.getExceptionUtil()
			.createApplicationException( "COSE key field " + key + " must be binary" );
	}

	private static byte[] getBinaryFieldOrNull( Cast cast, Struct cose, CFMLEngine eng, String key ) throws PageException {
		Object val = cose.get( cast.toKey( key ), null );
		if ( val == null ) return null;
		if ( eng.getDecisionUtil().isBinary( val ) ) {
			return cast.toBinary( val );
		}
		return null;
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "CoseToKey", 1, "coseKey", "COSE key is required", null );
		}
		return call( pc, args[0] );
	}
}
