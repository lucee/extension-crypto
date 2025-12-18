package org.lucee.extension.crypto;

import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.lucee.extension.crypto.util.JwtUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Creates a signed JWT (JWS).
 *
 * Usage:
 *   token = JwtSign( claims={sub: "user123"}, key="secret" )
 *   token = JwtSign( claims={sub: "user123"}, key=privateKeyPem, algorithm="RS256" )
 *   token = JwtSign( claims={sub: "user123"}, key="secret", expiresIn=3600 )
 */
public class JwtSign extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call(
		PageContext pc,
		Struct claims,
		Object key,
		String algorithm,
		Number expiresIn,
		String issuer,
		String audience,
		String kid
	) throws PageException {
		try {
			JwtUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Parse the key
			Object parsedKey = JwtUtil.parseKey( key, algorithm );

			// Determine algorithm
			JWSAlgorithm jwsAlg = JwtUtil.determineAlgorithm( parsedKey, algorithm );

			// Build claims from the struct - this properly handles all registered claims
			JWTClaimsSet baseClaims = JwtUtil.structToClaimsSet( claims );

			// Start a new builder from the base claims
			JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder( baseClaims );

			// Override with convenience parameters
			if ( issuer != null && !issuer.isEmpty() ) {
				claimsBuilder.issuer( issuer );
			}
			if ( audience != null && !audience.isEmpty() ) {
				claimsBuilder.audience( audience );
			}

			// Handle expiresIn (seconds from now) - only if no exp was already set in claims
			// (explicit exp in claims takes precedence over expiresIn convenience param)
			if ( expiresIn != null && expiresIn.longValue() > 0 && baseClaims.getExpirationTime() == null ) {
				long expTime = System.currentTimeMillis() + ( expiresIn.longValue() * 1000 );
				claimsBuilder.expirationTime( new Date( expTime ) );
			}

			// Set iat if not already set
			if ( baseClaims.getIssueTime() == null ) {
				claimsBuilder.issueTime( new Date() );
			}

			JWTClaimsSet finalClaims = claimsBuilder.build();

			// Build header
			JWSHeader.Builder headerBuilder = new JWSHeader.Builder( jwsAlg );
			if ( kid != null && !kid.isEmpty() ) {
				headerBuilder.keyID( kid );
			}
			JWSHeader header = headerBuilder.build();

			// Create and sign JWT
			SignedJWT jwt = new SignedJWT( header, finalClaims );
			JWSSigner signer = JwtUtil.createSigner( parsedKey, jwsAlg );
			jwt.sign( signer );

			return jwt.serialize();
		}
		catch ( Exception e ) {
			throw JwtUtil.toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "JwtSign", 2, "key",
				"claims and key are required", null
			);
		}

		Struct claims = cast.toStruct( args[0] );
		Object key = args[1];
		String algorithm = args.length > 2 && args[2] != null ? cast.toString( args[2] ) : null;
		Number expiresIn = args.length > 3 && args[3] != null ? cast.toDouble( args[3] ) : null;
		String issuer = args.length > 4 && args[4] != null ? cast.toString( args[4] ) : null;
		String audience = args.length > 5 && args[5] != null ? cast.toString( args[5] ) : null;
		String kid = args.length > 6 && args[6] != null ? cast.toString( args[6] ) : null;

		return call( pc, claims, key, algorithm, expiresIn, issuer, audience, kid );
	}
}
