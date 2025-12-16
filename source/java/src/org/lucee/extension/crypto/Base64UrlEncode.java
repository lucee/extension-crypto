package org.lucee.extension.crypto;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Encodes data using Base64URL encoding (URL-safe, no padding).
 *
 * Usage:
 *   encoded = Base64UrlEncode( "hello world" )
 *   encoded = Base64UrlEncode( binaryData )
 */
public class Base64UrlEncode extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object data ) throws PageException {
		try {
			byte[] bytes = CryptoUtil.toBytes( data );
			return CryptoUtil.base64UrlEncode( bytes );
		}
		catch ( PageException pe ) {
			throw pe;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "Base64UrlEncode", 1, "data", "Data is required", null );
		}
		return call( pc, args[0] );
	}
}
