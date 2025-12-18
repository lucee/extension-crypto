package org.lucee.extension.crypto;

import java.util.Map;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
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
 * Decodes a JWT without verifying the signature.
 * Useful for debugging and inspection.
 *
 * Usage:
 *   parts = JwtDecode( token )
 *   // parts.header = {alg: "RS256", typ: "JWT", ...}
 *   // parts.payload = {sub: "user123", exp: 1234567890, ...}
 *   // parts.signature = "base64url-signature"
 */
public class JwtDecode extends BIF {

	private static final long serialVersionUID = 1L;

	public static Struct call( PageContext pc, String token ) throws PageException {
		try {
			JwtUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Parse the JWT (doesn't verify)
			SignedJWT jwt = SignedJWT.parse( token );

			// Get header
			JWSHeader header = jwt.getHeader();
			Struct headerStruct = eng.getCreationUtil().createStruct();
			headerStruct.setEL( eng.getCastUtil().toKey( "alg" ), header.getAlgorithm().getName() );
			if ( header.getType() != null ) {
				headerStruct.setEL( eng.getCastUtil().toKey( "typ" ), header.getType().toString() );
			}
			if ( header.getKeyID() != null ) {
				headerStruct.setEL( eng.getCastUtil().toKey( "kid" ), header.getKeyID() );
			}
			if ( header.getContentType() != null ) {
				headerStruct.setEL( eng.getCastUtil().toKey( "cty" ), header.getContentType() );
			}
			// Add any custom header parameters
			Map<String, Object> customParams = header.getCustomParams();
			if ( customParams != null ) {
				for ( Map.Entry<String, Object> entry : customParams.entrySet() ) {
					headerStruct.setEL( eng.getCastUtil().toKey( entry.getKey() ), entry.getValue() );
				}
			}

			// Get payload (claims)
			JWTClaimsSet claims = jwt.getJWTClaimsSet();
			Struct payloadStruct = JwtUtil.claimsSetToStruct( claims );

			// Get signature (Base64URL encoded)
			Base64URL signature = jwt.getSignature();
			String signatureStr = signature != null ? signature.toString() : "";

			// Build result
			Struct result = eng.getCreationUtil().createStruct();
			result.setEL( eng.getCastUtil().toKey( "header" ), headerStruct );
			result.setEL( eng.getCastUtil().toKey( "payload" ), payloadStruct );
			result.setEL( eng.getCastUtil().toKey( "signature" ), signatureStr );

			return result;
		}
		catch ( Exception e ) {
			throw JwtUtil.toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 || args[0] == null ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "JwtDecode", 1, "token",
				"token is required", null
			);
		}

		String token = cast.toString( args[0] );
		return call( pc, token );
	}
}
