package org.lucee.extension.crypto;

import org.lucee.extension.crypto.util.OTPUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Generates an HOTP code for a given secret and counter (RFC 4226).
 *
 * Usage:
 *   code = HOTPGenerate( secret, counter )
 *   code = HOTPGenerate( secret, counter, { digits: 6, algorithm: "SHA1" } )
 */
public class HOTPGenerate extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, String secret, Number counter ) throws PageException {
		return call( pc, secret, counter, null );
	}

	public static String call( PageContext pc, String secret, Number counter, Struct options ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			int digits = OTPUtil.DEFAULT_DIGITS;
			String algorithm = OTPUtil.DEFAULT_ALGORITHM;

			if ( options != null ) {
				Object dVal = options.get( cast.toKey( "digits" ), null );
				if ( dVal != null ) digits = cast.toIntValue( dVal );

				Object aVal = options.get( cast.toKey( "algorithm" ), null );
				if ( aVal != null ) algorithm = cast.toString( aVal );
			}

			byte[] secretBytes = OTPUtil.base32Decode( secret );
			long counterVal = counter.longValue();

			return OTPUtil.generateHOTP( secretBytes, counterVal, digits, algorithm );
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
				.createFunctionException( pc, "HOTPGenerate", 2, "counter", "secret and counter are required", null );
		}

		String secret = cast.toString( args[0] );
		Number counter = cast.toLong( args[1] );
		Struct options = args.length > 2 && args[2] != null ? cast.toStruct( args[2] ) : null;

		return call( pc, secret, counter, options );
	}
}
