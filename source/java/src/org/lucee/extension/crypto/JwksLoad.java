package org.lucee.extension.crypto;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Array;
import lucee.runtime.type.Struct;

/**
 * Loads a JWKS (JSON Web Key Set) from a URL or JSON string, returns an array of JWK structs.
 *
 * Usage:
 *   keys = JwksLoad( "https://example.com/.well-known/jwks.json" )
 *   keys = JwksLoad( jwksJsonString )
 *
 * Each element in the returned array is a struct representing a single JWK,
 * suitable for passing to JwkToKey().
 *
 * Closes the loop for the JWT workflow: fetch provider's JWKS, find the right
 * key by kid, verify the token.
 */
public class JwksLoad extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String source ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			String json;

			// If it looks like a URL, fetch it
			if ( source.startsWith( "http://" ) ) {
				throw new IllegalArgumentException(
					"JWKS must be loaded over HTTPS, not plaintext HTTP: " + source );
			}
			if ( source.startsWith( "https://" ) ) {
				json = fetchUrl( source );
			}
			else {
				// Treat as raw JSON
				json = source;
			}

			JWKSet jwkSet = JWKSet.parse( json );
			List<JWK> keys = jwkSet.getKeys();

			Array result = eng.getCreationUtil().createArray();
			for ( JWK jwk : keys ) {
				Struct jwkStruct = CryptoUtil.mapToStruct( eng, jwk.toJSONObject() );
				result.appendEL( jwkStruct );
			}

			return result;
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	/**
	 * Fetch JSON from a URL using Java 11 HttpClient.
	 */
	private static String fetchUrl( String url ) throws Exception {
		HttpClient client = HttpClient.newBuilder()
			.connectTimeout( java.time.Duration.ofSeconds( 10 ) )
			.followRedirects( HttpClient.Redirect.NORMAL )
			.build();

		HttpRequest request = HttpRequest.newBuilder()
			.uri( URI.create( url ) )
			.header( "Accept", "application/json" )
			.GET()
			.build();

		HttpResponse<String> response = client.send( request, HttpResponse.BodyHandlers.ofString() );

		if ( response.statusCode() != 200 ) {
			throw new RuntimeException( "Failed to fetch JWKS from " + url + ": HTTP " + response.statusCode() );
		}

		return response.body();
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "JwksLoad", 1, "source", "URL or JSON string is required", null );
		}

		return call( pc, eng.getCastUtil().toString( args[0] ) );
	}
}
