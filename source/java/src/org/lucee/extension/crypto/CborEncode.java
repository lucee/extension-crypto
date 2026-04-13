package org.lucee.extension.crypto;

import java.util.Iterator;

import com.upokecenter.cbor.CBORObject;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Array;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;

/**
 * Encodes CFML values to CBOR binary format.
 *
 * Usage:
 *   cborBytes = CborEncode( data )
 */
public class CborEncode extends BIF {

	private static final long serialVersionUID = 1L;

	public static byte[] call( PageContext pc, Object data ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			CBORObject cbor = toCbor( eng, data );
			return cbor.EncodeToBytes();
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	/**
	 * Recursively convert a CFML value to a CBORObject.
	 */
	static CBORObject toCbor( CFMLEngine eng, Object value ) throws PageException {
		if ( value == null ) return CBORObject.Null;

		Cast cast = eng.getCastUtil();

		// Binary → byte string
		if ( eng.getDecisionUtil().isBinary( value ) ) {
			return CBORObject.FromObject( cast.toBinary( value ) );
		}

		// Struct → map
		if ( eng.getDecisionUtil().isStruct( value ) ) {
			Struct struct = cast.toStruct( value );
			CBORObject map = CBORObject.NewMap();
			Iterator<lucee.runtime.type.Collection.Key> it = struct.keyIterator();
			while ( it.hasNext() ) {
				lucee.runtime.type.Collection.Key key = it.next();
				String keyStr = key.getString();
				// Try to preserve integer keys (important for COSE)
				CBORObject cborKey;
				try {
					long intKey = Long.parseLong( keyStr );
					cborKey = CBORObject.FromObject( intKey );
				}
				catch ( NumberFormatException e ) {
					cborKey = CBORObject.FromObject( keyStr );
				}
				map.set( cborKey, toCbor( eng, struct.get( key ) ) );
			}
			return map;
		}

		// Array → array
		if ( eng.getDecisionUtil().isArray( value ) ) {
			Array arr = cast.toArray( value );
			CBORObject cborArr = CBORObject.NewArray();
			for ( int i = 1; i <= arr.size(); i++ ) {
				cborArr.Add( toCbor( eng, arr.getE( i ) ) );
			}
			return cborArr;
		}

		// Check Java type directly — CFML's isBoolean/isNumeric overlap
		// (isBoolean(42) is true in CFML, so checking isBoolean first would
		// encode every number as a boolean)
		if ( value instanceof Boolean ) {
			return CBORObject.FromObject( ( (Boolean) value ).booleanValue() );
		}

		if ( value instanceof Number ) {
			double d = ( (Number) value ).doubleValue();
			if ( d == Math.floor( d ) && !Double.isInfinite( d ) && d >= Long.MIN_VALUE && d <= Long.MAX_VALUE ) {
				return CBORObject.FromObject( (long) d );
			}
			return CBORObject.FromObject( d );
		}

		// String → text string
		if ( eng.getDecisionUtil().isSimpleValue( value ) ) {
			return CBORObject.FromObject( cast.toString( value ) );
		}

		// Fallback: convert to string
		return CBORObject.FromObject( cast.toString( value ) );
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "CborEncode", 1, "data", "Data is required", null );
		}
		return call( pc, args[0] );
	}
}
