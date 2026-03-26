package org.lucee.extension.crypto;

import java.security.SecureRandom;

import org.lucee.extension.crypto.util.OTPUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Generates a random TOTP/HOTP secret, returned as a Base32-encoded string.
 *
 * Usage:
 *   secret = TOTPSecret()          // 20 bytes (160-bit), standard for SHA1
 *   secret = TOTPSecret( 32 )      // 32 bytes (256-bit), for SHA256
 *   secret = TOTPSecret( 64 )      // 64 bytes (512-bit), for SHA512
 */
public class TOTPSecret extends BIF {

	private static final long serialVersionUID = 1L;
	private static final SecureRandom RANDOM = new SecureRandom();

	public static String call( PageContext pc ) throws PageException {
		return call( pc, OTPUtil.DEFAULT_SECRET_LENGTH );
	}

	public static String call( PageContext pc, Number length ) throws PageException {
		try {
			int len = length != null ? length.intValue() : OTPUtil.DEFAULT_SECRET_LENGTH;

			if ( len < 16 || len > 128 ) {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Secret length must be between 16 and 128 bytes" );
			}

			byte[] secret = new byte[len];
			RANDOM.nextBytes( secret );

			return OTPUtil.base32Encode( secret );
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

		Number length = args.length > 0 && args[0] != null ? cast.toInteger( args[0] ) : OTPUtil.DEFAULT_SECRET_LENGTH;

		return call( pc, length );
	}
}
