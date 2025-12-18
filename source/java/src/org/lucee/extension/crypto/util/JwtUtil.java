package org.lucee.extension.crypto.util;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.exp.PageException;
import lucee.runtime.type.Array;
import lucee.runtime.type.Collection;
import lucee.runtime.type.Struct;

/**
 * Utility class for JWT operations.
 */
public class JwtUtil {

	static {
		if ( Security.getProvider( BouncyCastleProvider.PROVIDER_NAME ) == null ) {
			Security.addProvider( new BouncyCastleProvider() );
		}
	}

	/**
	 * Ensures BouncyCastle provider is registered.
	 */
	public static void ensureProvider() {
		// Static initializer already handles this, but CryptoUtil also does it
		CryptoUtil.ensureProvider();
	}

	/**
	 * Parse a key from various formats.
	 * Accepts: String (PEM or secret), byte[], SecretKey, PrivateKey, PublicKey
	 */
	public static Object parseKey( Object key, String algorithm ) throws Exception {
		if ( key == null ) {
			throw new IllegalArgumentException( "Key cannot be null" );
		}

		// Already a Java key object
		if ( key instanceof PrivateKey || key instanceof PublicKey || key instanceof SecretKey ) {
			return key;
		}

		// byte[] - treat as secret for HMAC
		if ( key instanceof byte[] ) {
			return new SecretKeySpec( (byte[]) key, "HmacSHA256" );
		}

		// String - could be PEM or secret
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String keyStr = eng.getCastUtil().toString( key );

		// Check if it's PEM format - use CryptoUtil for parsing
		if ( keyStr.contains( "-----BEGIN" ) ) {
			return CryptoUtil.parsePem( keyStr );
		}

		// For HMAC algorithms, treat string as secret
		if ( algorithm != null && algorithm.toUpperCase().startsWith( "HS" ) ) {
			return new SecretKeySpec( keyStr.getBytes( "UTF-8" ), "HmacSHA256" );
		}

		// For non-HMAC algorithms, the key must be PEM format
		// Don't silently fall back to treating as secret - that would be a security issue
		throw new IllegalArgumentException(
			"Key must be in PEM format for algorithm " + algorithm + ". " +
			"Got a string that doesn't contain '-----BEGIN'. " +
			"For HMAC algorithms (HS256, HS384, HS512), pass the secret string directly."
		);
	}

	/**
	 * Determine the JWS algorithm based on key type.
	 */
	public static JWSAlgorithm determineAlgorithm( Object key, String requestedAlg ) throws Exception {
		// If algorithm is specified, use it
		if ( requestedAlg != null && !requestedAlg.trim().isEmpty() ) {
			return JWSAlgorithm.parse( requestedAlg.trim() );
		}

		// Auto-detect based on key type
		if ( key instanceof SecretKey || key instanceof byte[] ) {
			return JWSAlgorithm.HS256;
		}
		if ( key instanceof RSAPrivateKey || key instanceof RSAPublicKey ) {
			return JWSAlgorithm.RS256;
		}
		if ( key instanceof ECPrivateKey || key instanceof ECPublicKey ) {
			return JWSAlgorithm.ES256;
		}
		if ( key instanceof PrivateKey ) {
			String alg = ( (PrivateKey) key ).getAlgorithm();
			if ( "Ed25519".equalsIgnoreCase( alg ) || "EdDSA".equalsIgnoreCase( alg ) ) {
				return JWSAlgorithm.EdDSA;
			}
		}
		if ( key instanceof PublicKey ) {
			String alg = ( (PublicKey) key ).getAlgorithm();
			if ( "Ed25519".equalsIgnoreCase( alg ) || "EdDSA".equalsIgnoreCase( alg ) ) {
				return JWSAlgorithm.EdDSA;
			}
		}

		throw new IllegalArgumentException( "Cannot determine algorithm for key type: " + key.getClass().getName() );
	}

	/**
	 * Create a JWS signer for the given key and algorithm.
	 */
	public static JWSSigner createSigner( Object key, JWSAlgorithm algorithm ) throws Exception {
		// HMAC
		if ( algorithm.getName().startsWith( "HS" ) ) {
			if ( key instanceof SecretKey ) {
				return new MACSigner( (SecretKey) key );
			}
			if ( key instanceof byte[] ) {
				return new MACSigner( (byte[]) key );
			}
			if ( key instanceof String ) {
				return new MACSigner( (String) key );
			}
			throw new IllegalArgumentException( "HMAC algorithm requires a secret key, got: " + key.getClass().getName() );
		}

		// RSA
		if ( algorithm.getName().startsWith( "RS" ) || algorithm.getName().startsWith( "PS" ) ) {
			if ( key instanceof RSAPrivateKey ) {
				return new RSASSASigner( (RSAPrivateKey) key );
			}
			if ( key instanceof PrivateKey && "RSA".equalsIgnoreCase( ( (PrivateKey) key ).getAlgorithm() ) ) {
				return new RSASSASigner( (PrivateKey) key );
			}
			throw new IllegalArgumentException( "RSA algorithm requires an RSA private key, got: " + key.getClass().getName() );
		}

		// ECDSA
		if ( algorithm.getName().startsWith( "ES" ) ) {
			if ( key instanceof ECPrivateKey ) {
				return new ECDSASigner( (ECPrivateKey) key );
			}
			throw new IllegalArgumentException( "ECDSA algorithm requires an EC private key, got: " + key.getClass().getName() );
		}

		// EdDSA - not supported for now, would need additional setup
		if ( algorithm.equals( JWSAlgorithm.EdDSA ) ) {
			throw new IllegalArgumentException( "EdDSA is not yet supported. Use RS256 or ES256 instead." );
		}

		throw new IllegalArgumentException( "Unsupported algorithm: " + algorithm );
	}

	/**
	 * Create a JWS verifier for the given key and algorithm.
	 */
	public static JWSVerifier createVerifier( Object key, JWSAlgorithm algorithm ) throws Exception {
		// HMAC
		if ( algorithm.getName().startsWith( "HS" ) ) {
			if ( key instanceof SecretKey ) {
				return new MACVerifier( (SecretKey) key );
			}
			if ( key instanceof byte[] ) {
				return new MACVerifier( (byte[]) key );
			}
			if ( key instanceof String ) {
				return new MACVerifier( (String) key );
			}
			throw new IllegalArgumentException( "HMAC algorithm requires a secret key, got: " + key.getClass().getName() );
		}

		// RSA
		if ( algorithm.getName().startsWith( "RS" ) || algorithm.getName().startsWith( "PS" ) ) {
			if ( key instanceof RSAPublicKey ) {
				return new RSASSAVerifier( (RSAPublicKey) key );
			}
			throw new IllegalArgumentException( "RSA algorithm requires an RSA public key, got: " + key.getClass().getName() );
		}

		// ECDSA
		if ( algorithm.getName().startsWith( "ES" ) ) {
			if ( key instanceof ECPublicKey ) {
				return new ECDSAVerifier( (ECPublicKey) key );
			}
			throw new IllegalArgumentException( "ECDSA algorithm requires an EC public key, got: " + key.getClass().getName() );
		}

		// EdDSA - not supported for now
		if ( algorithm.equals( JWSAlgorithm.EdDSA ) ) {
			throw new IllegalArgumentException( "EdDSA is not yet supported. Use RS256 or ES256 instead." );
		}

		throw new IllegalArgumentException( "Unsupported algorithm: " + algorithm );
	}

	/**
	 * Convert a CFML struct to JWTClaimsSet.
	 */
	public static JWTClaimsSet structToClaimsSet( Struct claims ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		Collection.Key[] keys = claims.keys();
		for ( Collection.Key k : keys ) {
			String key = k.getString().toLowerCase();
			Object value = claims.get( k, null );

			switch ( key ) {
				case "iss":
				case "issuer":
					builder.issuer( eng.getCastUtil().toString( value ) );
					break;
				case "sub":
				case "subject":
					builder.subject( eng.getCastUtil().toString( value ) );
					break;
				case "aud":
				case "audience":
					if ( eng.getDecisionUtil().isArray( value ) ) {
						builder.audience( arrayToStringList( eng.getCastUtil().toArray( value ) ) );
					}
					else {
						builder.audience( eng.getCastUtil().toString( value ) );
					}
					break;
				case "exp":
				case "expirationtime":
					builder.expirationTime( toDate( value ) );
					break;
				case "nbf":
				case "notbefore":
					builder.notBeforeTime( toDate( value ) );
					break;
				case "iat":
				case "issueat":
				case "issuedat":
					builder.issueTime( toDate( value ) );
					break;
				case "jti":
				case "jwtid":
					builder.jwtID( eng.getCastUtil().toString( value ) );
					break;
				default:
					// Custom claim - use original case
					builder.claim( k.getString(), convertClaimValue( value ) );
			}
		}

		return builder.build();
	}

	/**
	 * Convert Array to List<String>.
	 */
	private static List<String> arrayToStringList( Array arr ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		List<String> result = new ArrayList<>();
		for ( int i = 1; i <= arr.size(); i++ ) {
			result.add( eng.getCastUtil().toString( arr.getE( i ) ) );
		}
		return result;
	}

	/**
	 * Convert a claim value to a type Nimbus can handle.
	 */
	private static Object convertClaimValue( Object value ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if ( value == null ) {
			return null;
		}
		if ( value instanceof String || value instanceof Number || value instanceof Boolean ) {
			return value;
		}
		if ( eng.getDecisionUtil().isDate( value, false ) ) {
			return eng.getCastUtil().toDate( value, null );
		}
		if ( eng.getDecisionUtil().isArray( value ) ) {
			return eng.getCastUtil().toList( eng.getCastUtil().toArray( value ) );
		}
		if ( eng.getDecisionUtil().isStruct( value ) ) {
			return eng.getCastUtil().toMap( eng.getCastUtil().toStruct( value ) );
		}
		return eng.getCastUtil().toString( value );
	}

	/**
	 * Convert various types to Date.
	 */
	private static Date toDate( Object value ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		// Handle CFML date objects first (lucee.runtime.type.dt.DateTime extends Date)
		// Force a fresh java.util.Date to avoid any Lucee DateTime weirdness
		if ( eng.getDecisionUtil().isDate( value, false ) ) {
			Date d = eng.getCastUtil().toDate( value, null );
			if ( d != null ) return new Date( d.getTime() );
		}
		if ( value instanceof Date ) {
			return new Date( ( (Date) value ).getTime() );
		}
		if ( value instanceof Number ) {
			// JWT spec (RFC 7519) says numeric dates are always Unix epoch seconds
			long num = ( (Number) value ).longValue();
			return new Date( num * 1000 );
		}
		Date d = eng.getCastUtil().toDate( value, null );
		return d != null ? new Date( d.getTime() ) : null;
	}

	/**
	 * Convert JWTClaimsSet to a CFML struct.
	 */
	public static Struct claimsSetToStruct( JWTClaimsSet claims ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Struct result = eng.getCreationUtil().createStruct();

		Map<String, Object> claimsMap = claims.getClaims();
		for ( Map.Entry<String, Object> entry : claimsMap.entrySet() ) {
			result.setEL( eng.getCastUtil().toKey( entry.getKey() ), entry.getValue() );
		}

		return result;
	}

	/**
	 * Convert an exception to a PageException.
	 */
	public static PageException toPageException( Exception e ) {
		return CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
	}
}
