package org.lucee.extension.crypto;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.lucee.extension.crypto.util.OTPUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Generates an otpauth:// URI for TOTP, suitable for QR code generation.
 *
 * Usage:
 *   uri = TOTPGenerateUri( secret, "user@example.com", "MyApp" )
 *   uri = TOTPGenerateUri( secret, "user@example.com", "MyApp", { digits: 6, period: 30, algorithm: "SHA1" } )
 *
 * Produces: otpauth://totp/MyApp:user@example.com?secret=BASE32&issuer=MyApp&algorithm=SHA1&digits=6&period=30
 */
public class TOTPGenerateUri extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, String secret, String account, String issuer ) throws PageException {
		return call( pc, secret, account, issuer, null );
	}

	public static String call( PageContext pc, String secret, String account, String issuer, Struct options ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			int digits = OTPUtil.DEFAULT_DIGITS;
			int period = OTPUtil.DEFAULT_PERIOD;
			String algorithm = OTPUtil.DEFAULT_ALGORITHM;

			if ( options != null ) {
				Object dVal = options.get( cast.toKey( "digits" ), null );
				if ( dVal != null ) digits = cast.toIntValue( dVal );

				Object pVal = options.get( cast.toKey( "period" ), null );
				if ( pVal != null ) period = cast.toIntValue( pVal );

				Object aVal = options.get( cast.toKey( "algorithm" ), null );
				if ( aVal != null ) algorithm = cast.toString( aVal );
			}

			String alg = OTPUtil.toOtpauthAlgorithm( algorithm );

			// Build URI per https://github.com/google/google-authenticator/wiki/Key-Uri-Format
			StringBuilder sb = new StringBuilder( "otpauth://totp/" );
			sb.append( urlEncode( issuer ) ).append( ":" ).append( urlEncode( account ) );
			sb.append( "?secret=" ).append( secret.replaceAll( "\\s", "" ) );
			sb.append( "&issuer=" ).append( urlEncode( issuer ) );
			sb.append( "&algorithm=" ).append( alg );
			sb.append( "&digits=" ).append( digits );
			sb.append( "&period=" ).append( period );

			return sb.toString();
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	private static String urlEncode( String value ) {
		return URLEncoder.encode( value, StandardCharsets.UTF_8 );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 3 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "TOTPGenerateUri", 3, "issuer", "secret, account, and issuer are required", null );
		}

		String secret = cast.toString( args[0] );
		String account = cast.toString( args[1] );
		String issuer = cast.toString( args[2] );
		Struct options = args.length > 3 && args[3] != null ? cast.toStruct( args[3] ) : null;

		return call( pc, secret, account, issuer, options );
	}
}
