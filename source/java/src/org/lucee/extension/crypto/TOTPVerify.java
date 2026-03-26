package org.lucee.extension.crypto;

import org.lucee.extension.crypto.util.CryptoUtil;
import org.lucee.extension.crypto.util.OTPUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Verifies a TOTP code against a shared secret (RFC 6238).
 *
 * Usage:
 *   isValid = TOTPVerify( secret, "123456" )
 *   isValid = TOTPVerify( secret, "123456", { window: 1, digits: 6, period: 30, algorithm: "SHA1" } )
 *
 * The window parameter allows for clock skew — window=1 checks the previous,
 * current, and next time steps (default).
 */
public class TOTPVerify extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String secret, String code ) throws PageException {
		return call( pc, secret, code, null );
	}

	public static Object call( PageContext pc, String secret, String code, Struct options ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			int digits = OTPUtil.DEFAULT_DIGITS;
			int period = OTPUtil.DEFAULT_PERIOD;
			String algorithm = OTPUtil.DEFAULT_ALGORITHM;
			int window = OTPUtil.DEFAULT_WINDOW;

			if ( options != null ) {
				Object dVal = options.get( cast.toKey( "digits" ), null );
				if ( dVal != null ) digits = cast.toIntValue( dVal );

				Object pVal = options.get( cast.toKey( "period" ), null );
				if ( pVal != null ) period = cast.toIntValue( pVal );

				Object aVal = options.get( cast.toKey( "algorithm" ), null );
				if ( aVal != null ) algorithm = cast.toString( aVal );

				Object wVal = options.get( cast.toKey( "window" ), null );
				if ( wVal != null ) window = cast.toIntValue( wVal );
			}

			byte[] secretBytes = OTPUtil.base32Decode( secret );
			long currentTime = System.currentTimeMillis() / 1000;
			long counter = OTPUtil.getTimeCounter( currentTime, period );

			// Check within the window (counter - window to counter + window)
			for ( long i = counter - window; i <= counter + window; i++ ) {
				String expected = OTPUtil.generateHOTP( secretBytes, i, digits, algorithm );
				if ( CryptoUtil.constantTimeEquals( expected, code ) ) {
					return true;
				}
			}

			return false;
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "TOTPVerify", 2, "code", "secret and code are required", null );
		}

		String secret = cast.toString( args[0] );
		String code = cast.toString( args[1] );
		Struct options = args.length > 2 && args[2] != null ? cast.toStruct( args[2] ) : null;

		return call( pc, secret, code, options );
	}
}
