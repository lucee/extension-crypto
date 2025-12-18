package org.lucee.extension.crypto;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.lucee.extension.crypto.util.JwtUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Array;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Verifies a signed JWT and returns the claims.
 *
 * Usage:
 *   claims = JwtVerify( token=token, key="secret" )
 *   claims = JwtVerify( token=token, key=publicKeyPem )
 *   claims = JwtVerify( token=token, key=publicKeyPem, issuer="https://myapp.com" )
 *   result = JwtVerify( token=token, key=publicKeyPem, throwOnError=false )
 */
public class JwtVerify extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call(
		PageContext pc,
		String token,
		Object key,
		Object algorithms,
		String issuer,
		String audience,
		Number clockSkew,
		Boolean throwOnError
	) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		boolean shouldThrow = throwOnError == null || throwOnError;

		try {
			JwtUtil.ensureProvider();

			// Parse the JWT
			SignedJWT jwt = SignedJWT.parse( token );
			JWSAlgorithm tokenAlg = jwt.getHeader().getAlgorithm();

			// SECURITY: Reject "none" algorithm - prevents signature bypass attacks
			if ( tokenAlg.getName().equalsIgnoreCase( "none" ) ) {
				return handleError( eng, shouldThrow, "Algorithm 'none' is not allowed" );
			}

			// Check allowed algorithms
			Set<String> allowedAlgs = parseAllowedAlgorithms( algorithms );
			if ( allowedAlgs != null && !allowedAlgs.isEmpty() ) {
				if ( !allowedAlgs.contains( tokenAlg.getName() ) ) {
					return handleError( eng, shouldThrow, "Algorithm " + tokenAlg.getName() + " is not allowed" );
				}
			}

			// Parse the key
			Object parsedKey = JwtUtil.parseKey( key, tokenAlg.getName() );

			// Create verifier and verify signature
			JWSVerifier verifier = JwtUtil.createVerifier( parsedKey, tokenAlg );
			if ( !jwt.verify( verifier ) ) {
				return handleError( eng, shouldThrow, "Invalid signature" );
			}

			// Get claims
			JWTClaimsSet claims = jwt.getJWTClaimsSet();

			// Validate issuer
			if ( issuer != null && !issuer.isEmpty() ) {
				if ( claims.getIssuer() == null || !claims.getIssuer().equals( issuer ) ) {
					return handleError( eng, shouldThrow, "Invalid issuer: expected " + issuer + ", got " + claims.getIssuer() );
				}
			}

			// Validate audience
			if ( audience != null && !audience.isEmpty() ) {
				List<String> audList = claims.getAudience();
				if ( audList == null || !audList.contains( audience ) ) {
					return handleError( eng, shouldThrow, "Invalid audience: expected " + audience );
				}
			}

			// Validate expiration
			long skewMs = clockSkew != null ? clockSkew.longValue() * 1000 : 0;
			Date now = new Date();

			if ( claims.getExpirationTime() != null ) {
				Date expWithSkew = new Date( claims.getExpirationTime().getTime() + skewMs );
				if ( now.after( expWithSkew ) ) {
					return handleError( eng, shouldThrow, "Token has expired" );
				}
			}

			// Validate not before
			if ( claims.getNotBeforeTime() != null ) {
				Date nbfWithSkew = new Date( claims.getNotBeforeTime().getTime() - skewMs );
				if ( now.before( nbfWithSkew ) ) {
					return handleError( eng, shouldThrow, "Token is not yet valid" );
				}
			}

			// Success - return claims
			Struct claimsStruct = JwtUtil.claimsSetToStruct( claims );

			if ( !shouldThrow ) {
				// Return result struct with valid=true
				Struct result = eng.getCreationUtil().createStruct();
				result.setEL( eng.getCastUtil().toKey( "valid" ), Boolean.TRUE );
				result.setEL( eng.getCastUtil().toKey( "claims" ), claimsStruct );
				return result;
			}

			return claimsStruct;
		}
		catch ( Exception e ) {
			return handleError( eng, shouldThrow, e.getMessage(), e );
		}
	}

	private static Set<String> parseAllowedAlgorithms( Object algorithms ) throws PageException {
		if ( algorithms == null ) {
			return null;
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Set<String> result = new HashSet<>();

		if ( eng.getDecisionUtil().isArray( algorithms ) ) {
			Array arr = eng.getCastUtil().toArray( algorithms );
			for ( int i = 1; i <= arr.size(); i++ ) {
				String alg = eng.getCastUtil().toString( arr.getE( i ) ).trim().toUpperCase();
				if ( !alg.isEmpty() ) {
					result.add( alg );
				}
			}
		}
		else if ( algorithms instanceof String ) {
			String algStr = (String) algorithms;
			if ( algStr.contains( "," ) ) {
				for ( String alg : algStr.split( "," ) ) {
					String trimmed = alg.trim().toUpperCase();
					if ( !trimmed.isEmpty() ) {
						result.add( trimmed );
					}
				}
			}
			else {
				String trimmed = algStr.trim().toUpperCase();
				if ( !trimmed.isEmpty() ) {
					result.add( trimmed );
				}
			}
		}

		// Return null if no valid algorithms were found (allows any)
		return result.isEmpty() ? null : result;
	}

	private static Object handleError( CFMLEngine eng, boolean shouldThrow, String message ) throws PageException {
		return handleError( eng, shouldThrow, message, null );
	}

	private static Object handleError( CFMLEngine eng, boolean shouldThrow, String message, Exception cause ) throws PageException {
		if ( shouldThrow ) {
			if ( cause != null ) {
				throw JwtUtil.toPageException( new RuntimeException( message, cause ) );
			}
			throw eng.getExceptionUtil().createApplicationException( message );
		}

		// Return result struct with valid=false
		Struct result = eng.getCreationUtil().createStruct();
		result.setEL( eng.getCastUtil().toKey( "valid" ), Boolean.FALSE );
		result.setEL( eng.getCastUtil().toKey( "error" ), message );
		return result;
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "JwtVerify", 2, "key",
				"token and key are required", null
			);
		}

		String token = cast.toString( args[0] );
		Object key = args[1];
		Object algorithms = args.length > 2 && args[2] != null ? args[2] : null;
		String issuer = args.length > 3 && args[3] != null ? cast.toString( args[3] ) : null;
		String audience = args.length > 4 && args[4] != null ? cast.toString( args[4] ) : null;
		Number clockSkew = args.length > 5 && args[5] != null ? cast.toDouble( args[5] ) : null;
		Boolean throwOnError = args.length > 6 && args[6] != null ? cast.toBoolean( args[6] ) : null;

		return call( pc, token, key, algorithms, issuer, audience, clockSkew, throwOnError );
	}
}
