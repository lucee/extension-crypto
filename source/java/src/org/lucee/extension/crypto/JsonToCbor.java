package org.lucee.extension.crypto;

import com.upokecenter.cbor.CBORObject;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Converts a JSON string to CBOR-encoded bytes.
 *
 * Usage:
 *   cborBytes = JsonToCbor( jsonString )
 */
public class JsonToCbor extends BIF {

	private static final long serialVersionUID = 1L;

	public static byte[] call( PageContext pc, String json ) throws PageException {
		try {
			CBORObject cbor = CBORObject.FromJSONString( json );
			return cbor.EncodeToBytes();
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

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "JsonToCbor", 1, "json", "JSON string is required", null );
		}

		return call( pc, cast.toString( args[0] ) );
	}
}
