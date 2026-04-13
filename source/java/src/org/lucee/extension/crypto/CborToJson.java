package org.lucee.extension.crypto;

import com.upokecenter.cbor.CBORObject;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Converts CBOR-encoded bytes directly to a JSON string.
 *
 * Usage:
 *   json = CborToJson( cborBytes )
 */
public class CborToJson extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object data ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			byte[] bytes;
			if ( eng.getDecisionUtil().isBinary( data ) ) {
				bytes = eng.getCastUtil().toBinary( data );
			}
			else {
				throw new IllegalArgumentException( "CborToJson requires binary data. Use ToBinary() or Base64UrlDecode() to convert your input first." );
			}

			CBORObject cbor = CBORObject.DecodeFromBytes( bytes );
			return cbor.ToJSONString();
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "CborToJson", 1, "data", "CBOR binary data is required", null );
		}
		return call( pc, args[0] );
	}
}
