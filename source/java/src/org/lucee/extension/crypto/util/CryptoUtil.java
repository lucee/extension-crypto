package org.lucee.extension.crypto.util;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.exp.PageException;

/**
 * Utility class for cryptographic operations using BouncyCastle.
 */
public class CryptoUtil {

	static {
		if ( Security.getProvider( BouncyCastleProvider.PROVIDER_NAME ) == null ) {
			Security.addProvider( new BouncyCastleProvider() );
		}
	}

	/**
	 * Ensures BouncyCastle provider is registered.
	 */
	public static void ensureProvider() {
		// Static initializer already handles this
	}

	/**
	 * Parse algorithm string to extract type and size/curve.
	 * Examples: "RSA-2048" -> ["RSA", "2048"], "P-256" -> ["EC", "P-256"], "Ed25519" -> ["EdDSA", "Ed25519"]
	 */
	public static String[] parseAlgorithm( String algorithm ) {
		algorithm = algorithm.trim();

		// Handle RSA with size
		if ( algorithm.toUpperCase().startsWith( "RSA" ) ) {
			if ( algorithm.contains( "-" ) ) {
				String[] parts = algorithm.split( "-", 2 );
				return new String[] { "RSA", parts[1] };
			}
			return new String[] { "RSA", "2048" }; // default
		}

		// Handle EC curves
		if ( algorithm.equalsIgnoreCase( "EC" ) ) {
			return new String[] { "EC", "P-256" }; // default
		}
		if ( algorithm.toUpperCase().startsWith( "P-" ) ) {
			return new String[] { "EC", algorithm };
		}
		if ( algorithm.equalsIgnoreCase( "secp256r1" ) || algorithm.equalsIgnoreCase( "prime256v1" ) ) {
			return new String[] { "EC", "P-256" };
		}
		if ( algorithm.equalsIgnoreCase( "secp384r1" ) ) {
			return new String[] { "EC", "P-384" };
		}
		if ( algorithm.equalsIgnoreCase( "secp521r1" ) ) {
			return new String[] { "EC", "P-521" };
		}

		// Handle EdDSA
		if ( algorithm.equalsIgnoreCase( "Ed25519" ) || algorithm.equalsIgnoreCase( "Ed448" ) ) {
			return new String[] { "EdDSA", algorithm };
		}

		// Handle post-quantum ML-KEM (formerly Kyber)
		if ( algorithm.toUpperCase().startsWith( "KYBER" ) || algorithm.toUpperCase().startsWith( "ML-KEM" ) ) {
			String size;
			if ( algorithm.equalsIgnoreCase( "Kyber" ) || algorithm.equalsIgnoreCase( "ML-KEM" ) ) {
				size = "768";
			}
			else {
				size = algorithm.replaceAll( "(?i)(kyber|ml-kem-?)", "" );
			}
			return new String[] { "ML-KEM", size };
		}
		if ( algorithm.toUpperCase().startsWith( "DILITHIUM" ) ) {
			if ( algorithm.equalsIgnoreCase( "Dilithium" ) ) {
				return new String[] { "Dilithium", "3" };
			}
			String level = algorithm.replaceAll( "(?i)dilithium", "" );
			return new String[] { "Dilithium", level };
		}

		// Default: treat as algorithm name directly
		return new String[] { algorithm, null };
	}

	/**
	 * Generate a key pair for the specified algorithm.
	 */
	public static KeyPair generateKeyPair( String algorithm ) throws Exception {
		ensureProvider();
		String[] parsed = parseAlgorithm( algorithm );
		String type = parsed[0];
		String param = parsed[1];

		KeyPairGenerator kpg;

		switch ( type.toUpperCase() ) {
			case "RSA":
				kpg = KeyPairGenerator.getInstance( "RSA", "BC" );
				kpg.initialize( Integer.parseInt( param ) );
				return kpg.generateKeyPair();

			case "EC":
				kpg = KeyPairGenerator.getInstance( "EC", "BC" );
				String curveName = ecCurveName( param );
				kpg.initialize( new ECGenParameterSpec( curveName ) );
				return kpg.generateKeyPair();

			case "EDDSA":
				// EdDSA uses the curve name directly as algorithm
				kpg = KeyPairGenerator.getInstance( param, "BC" );
				return kpg.generateKeyPair();

			case "ML-KEM":
				// Post-quantum KEM (formerly Kyber)
				String mlkemAlg = "ML-KEM-" + param;
				kpg = KeyPairGenerator.getInstance( mlkemAlg, "BC" );
				return kpg.generateKeyPair();

			case "DILITHIUM":
				// Post-quantum signatures
				String dilAlg = "DILITHIUM" + param;
				kpg = KeyPairGenerator.getInstance( dilAlg, "BC" );
				return kpg.generateKeyPair();

			default:
				throw new IllegalArgumentException( "Unsupported algorithm: " + algorithm +
					". Supported algorithms are: RSA-{keysize}, EC/P-256/P-384/P-521, Ed25519, Ed448, ML-KEM/Kyber, Dilithium" );
		}
	}

	/**
	 * Convert EC curve parameter to standard name.
	 */
	private static String ecCurveName( String curve ) {
		switch ( curve.toUpperCase() ) {
			case "P-256":
				return "secp256r1";
			case "P-384":
				return "secp384r1";
			case "P-521":
				return "secp521r1";
			default:
				return curve;
		}
	}

	/**
	 * Convert a Key or Certificate to PEM format.
	 * For private keys, defaults to traditional format (BouncyCastle default).
	 * Use toPemPKCS8() for PKCS#8 format.
	 */
	public static String toPem( Object obj ) throws IOException {
		ensureProvider();
		StringWriter sw = new StringWriter();
		try ( JcaPEMWriter pw = new JcaPEMWriter( sw ) ) {
			pw.writeObject( obj );
		}
		return sw.toString();
	}

	/**
	 * Convert a PrivateKey to PKCS#8 PEM format (-----BEGIN PRIVATE KEY-----).
	 * This is the modern, algorithm-agnostic format.
	 */
	public static String toPemPKCS8( PrivateKey privateKey ) throws IOException {
		ensureProvider();
		StringWriter sw = new StringWriter();
		// Use PemWriter directly with PemObject to avoid MiscPEMGenerator's algorithm-specific formatting
		try ( org.bouncycastle.util.io.pem.PemWriter pw = new org.bouncycastle.util.io.pem.PemWriter( sw ) ) {
			pw.writeObject( new org.bouncycastle.util.io.pem.PemObject( "PRIVATE KEY", privateKey.getEncoded() ) );
		}
		return sw.toString();
	}

	/**
	 * Convert a PrivateKey to traditional PEM format (-----BEGIN RSA PRIVATE KEY-----, etc).
	 * This is the algorithm-specific format. Not all algorithms support this.
	 */
	public static String toPemTraditional( PrivateKey privateKey ) throws IOException {
		ensureProvider();
		StringWriter sw = new StringWriter();
		try ( JcaPEMWriter pw = new JcaPEMWriter( sw ) ) {
			pw.writeObject( privateKey );
		}
		return sw.toString();
	}

	/**
	 * Parse a PEM string and return the appropriate object.
	 */
	public static Object parsePem( String pem ) throws Exception {
		ensureProvider();
		try ( PEMParser parser = new PEMParser( new StringReader( pem ) ) ) {
			Object obj = parser.readObject();
			if ( obj == null ) {
				throw new IllegalArgumentException( "Could not parse PEM content" );
			}

			JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider( "BC" );

			if ( obj instanceof PEMKeyPair ) {
				return keyConverter.getKeyPair( (PEMKeyPair) obj );
			}
			else if ( obj instanceof PrivateKeyInfo ) {
				return keyConverter.getPrivateKey( (PrivateKeyInfo) obj );
			}
			else if ( obj instanceof SubjectPublicKeyInfo ) {
				return keyConverter.getPublicKey( (SubjectPublicKeyInfo) obj );
			}
			else if ( obj instanceof X509CertificateHolder ) {
				return new JcaX509CertificateConverter().setProvider( "BC" )
					.getCertificate( (X509CertificateHolder) obj );
			}

			throw new IllegalArgumentException( "Unknown PEM type: " + obj.getClass().getName() );
		}
	}

	/**
	 * Parse a PEM string and return a PrivateKey.
	 */
	public static PrivateKey parsePrivateKey( String pem ) throws Exception {
		Object obj = parsePem( pem );
		if ( obj instanceof PrivateKey ) {
			return (PrivateKey) obj;
		}
		if ( obj instanceof KeyPair ) {
			return ( (KeyPair) obj ).getPrivate();
		}
		throw new IllegalArgumentException( "PEM does not contain a private key" );
	}

	/**
	 * Parse a PEM string and return a PublicKey.
	 */
	public static PublicKey parsePublicKey( String pem ) throws Exception {
		Object obj = parsePem( pem );
		if ( obj instanceof PublicKey ) {
			return (PublicKey) obj;
		}
		if ( obj instanceof KeyPair ) {
			return ( (KeyPair) obj ).getPublic();
		}
		if ( obj instanceof X509Certificate ) {
			return ( (X509Certificate) obj ).getPublicKey();
		}
		throw new IllegalArgumentException( "PEM does not contain a public key" );
	}

	/**
	 * Parse a PEM string and return an X509Certificate.
	 */
	public static X509Certificate parseCertificate( String pem ) throws Exception {
		Object obj = parsePem( pem );
		if ( obj instanceof X509Certificate ) {
			return (X509Certificate) obj;
		}
		throw new IllegalArgumentException( "PEM does not contain a certificate" );
	}

	/**
	 * Convert Base64-encoded key bytes to a PrivateKey.
	 */
	public static PrivateKey base64ToPrivateKey( String base64, String algorithm ) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode( base64 );
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
		KeyFactory kf = KeyFactory.getInstance( algorithm, "BC" );
		return kf.generatePrivate( spec );
	}

	/**
	 * Convert Base64-encoded key bytes to a PublicKey.
	 */
	public static PublicKey base64ToPublicKey( String base64, String algorithm ) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode( base64 );
		X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
		KeyFactory kf = KeyFactory.getInstance( algorithm, "BC" );
		return kf.generatePublic( spec );
	}

	/**
	 * Base64URL encode (no padding).
	 */
	public static String base64UrlEncode( byte[] data ) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString( data );
	}

	/**
	 * Base64URL decode.
	 */
	public static byte[] base64UrlDecode( String encoded ) {
		return Base64.getUrlDecoder().decode( encoded );
	}

	/**
	 * Convert CFML value to bytes.
	 */
	public static byte[] toBytes( Object value ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		if ( eng.getDecisionUtil().isBinary( value ) ) {
			return eng.getCastUtil().toBinary( value );
		}
		return eng.getCastUtil().toString( value ).getBytes( StandardCharsets.UTF_8 );
	}

	/**
	 * Determine signature algorithm based on key type.
	 */
	public static String getSignatureAlgorithm( Key key ) {
		String keyAlg = key.getAlgorithm();
		String upperAlg = keyAlg.toUpperCase();

		// Handle Dilithium variants (DILITHIUM2, DILITHIUM3, DILITHIUM5)
		if ( upperAlg.startsWith( "DILITHIUM" ) ) {
			return keyAlg;
		}

		switch ( upperAlg ) {
			case "RSA":
				return "SHA256withRSA";
			case "EC":
			case "ECDSA":
				return "SHA256withECDSA";
			case "ED25519":
				return "Ed25519";
			case "ED448":
				return "Ed448";
			default:
				return "SHA256with" + keyAlg;
		}
	}

	/**
	 * Convert an exception to a PageException, preserving the cause and stacktrace.
	 */
	public static PageException toPageException( Exception e ) {
		return CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
	}
}
