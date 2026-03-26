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
 * Verifies an HOTP code against a secret and counter (RFC 4226).
 *
 * Usage:
 *   isValid = HOTPVerify( secret, "123456", counter )
 *   isValid = HOTPVerify( secret, "123456", counter, { digits: 6, algorithm: "SHA1", window: 0 } )
 *
 * The window parameter allows for counter desync — window=0 checks only the
 * exact counter (default). window=5 checks counter through counter+5.
 */
public class HOTPVerify extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String secret, String code, Number counter ) throws PageException {
		return call( pc, secret, code, counter, null );
	}

	public static Object call( PageContext pc, String secret, String code, Number counter, Struct options ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			int digits = OTPUtil.DEFAULT_DIGITS;
			String algorithm = OTPUtil.DEFAULT_ALGORITHM;
			int window = 0;

			if ( options != null ) {
				Object dVal = options.get( cast.toKey( "digits" ), null );
				if ( dVal != null ) digits = cast.toIntValue( dVal );

				Object aVal = options.get( cast.toKey( "algorithm" ), null );
				if ( aVal != null ) algorithm = cast.toString( aVal );

				Object wVal = options.get( cast.toKey( "window" ), null );
				if ( wVal != null ) window = cast.toIntValue( wVal );
			}

			byte[] secretBytes = OTPUtil.base32Decode( secret );
			long counterVal = counter.longValue();

			// Check from counter to counter + window
			for ( long i = counterVal; i <= counterVal + window; i++ ) {
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

		if ( args.length < 3 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "HOTPVerify", 3, "counter", "secret, code, and counter are required", null );
		}

		String secret = cast.toString( args[0] );
		String code = cast.toString( args[1] );
		Number counter = cast.toLong( args[2] );
		Struct options = args.length > 3 && args[3] != null ? cast.toStruct( args[3] ) : null;

		return call( pc, secret, code, counter, options );
	}
}
