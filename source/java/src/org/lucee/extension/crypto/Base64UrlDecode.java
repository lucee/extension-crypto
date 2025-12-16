package org.lucee.extension.crypto;

import java.nio.charset.Charset;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Decodes a Base64URL-encoded string.
 *
 * Usage:
 *   binary = Base64UrlDecode( encoded )
 *   string = Base64UrlDecode( encoded, "UTF-8" )
 */
public class Base64UrlDecode extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, String encoded ) throws PageException {
		return call( pc, encoded, null );
	}

	public static Object call( PageContext pc, String encoded, String charset ) throws PageException {
		try {
			byte[] bytes = CryptoUtil.base64UrlDecode( encoded );

			if ( charset != null && !charset.isEmpty() ) {
				return new String( bytes, Charset.forName( charset ) );
			}

			return bytes;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "Base64UrlDecode", 1, "encoded", "Encoded string is required", null );
		}

		CFMLEngine eng = CFMLEngineFactory.getInstance();
		String encoded = eng.getCastUtil().toString( args[0] );
		String charset = args.length > 1 && args[1] != null ? eng.getCastUtil().toString( args[1] ) : null;

		return call( pc, encoded, charset );
	}
}
