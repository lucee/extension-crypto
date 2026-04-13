package org.lucee.extension.crypto;

import java.util.Collection;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Array;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Cast;
import lucee.runtime.util.Creation;

/**
 * Decodes CBOR-encoded bytes to CFML types.
 *
 * Usage:
 *   result = CborDecode( cborBytes )
 *   result = CborDecode( cborBytes, { preserveTags: false } )
 */
public class CborDecode extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, Object data ) throws PageException {
		return call( pc, data, null );
	}

	public static Object call( PageContext pc, Object data, Struct options ) throws PageException {
		try {
			CFMLEngine eng = CFMLEngineFactory.getInstance();
			Cast cast = eng.getCastUtil();

			byte[] bytes;
			if ( eng.getDecisionUtil().isBinary( data ) ) {
				bytes = cast.toBinary( data );
			}
			else {
				throw new IllegalArgumentException( "CborDecode requires binary data. Use ToBinary() or Base64UrlDecode() to convert your input first." );
			}

			boolean preserveTags = true;
			if ( options != null ) {
				Object pt = options.get( cast.toKey( "preserveTags" ), null );
				if ( pt != null ) {
					preserveTags = cast.toBooleanValue( pt );
				}
			}

			CBORObject cbor = CBORObject.DecodeFromBytes( bytes );
			return toCfml( eng, cbor, preserveTags );
		}
		catch ( Exception e ) {
			if ( e instanceof PageException ) throw (PageException) e;
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	/**
	 * Recursively convert a CBORObject to CFML types.
	 */
	static Object toCfml( CFMLEngine eng, CBORObject cbor, boolean preserveTags ) throws PageException {
		if ( cbor == null || cbor.isNull() ) return null;

		Cast cast = eng.getCastUtil();
		Creation create = eng.getCreationUtil();

		// Handle tagged values
		if ( cbor.isTagged() ) {
			// Untag() strips the outermost tag, so read that one
			long tag = cbor.getMostOuterTag().ToInt64Checked();
			Object innerValue = toCfml( eng, cbor.Untag(), preserveTags );

			if ( preserveTags ) {
				Struct tagged = create.createStruct();
				tagged.set( cast.toKey( "tag" ), tag );
				tagged.set( cast.toKey( "value" ), innerValue );
				return tagged;
			}
			return innerValue;
		}

		CBORType type = cbor.getType();

		switch ( type ) {
			case Map: {
				Struct result = create.createStruct();
				Collection<CBORObject> keys = cbor.getKeys();
				for ( CBORObject key : keys ) {
					// CBOR map keys can be any type; use the natural representation
					lucee.runtime.type.Collection.Key cfmlKey;
					if ( key.getType() == CBORType.TextString ) {
						cfmlKey = cast.toKey( key.AsString() );
					}
					else if ( key.getType() == CBORType.Integer ) {
						cfmlKey = cast.toKey( String.valueOf( key.AsInt64Value() ) );
					}
					else {
						cfmlKey = cast.toKey( key.toString() );
					}
					result.set( cfmlKey, toCfml( eng, cbor.get( key ), preserveTags ) );
				}
				return result;
			}

			case Array: {
				Array result = create.createArray();
				for ( int i = 0; i < cbor.size(); i++ ) {
					result.append( toCfml( eng, cbor.get( i ), preserveTags ) );
				}
				return result;
			}

			case TextString:
				return cbor.AsString();

			case ByteString:
				return cbor.GetByteString();

			case Integer:
				// Use long for values that fit, otherwise BigInteger
				if ( cbor.CanValueFitInInt64() ) {
					long val = cbor.AsInt64Value();
					if ( val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE ) {
						return (int) val;
					}
					return val;
				}
				return cbor.ToObject( java.math.BigInteger.class );

			case FloatingPoint:
				return cbor.AsDouble();

			case Boolean:
				return cbor.AsBoolean();

			case SimpleValue:
				// CBOR simple values: undefined maps to null
				return null;

			default:
				return cbor.toString();
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil()
				.createFunctionException( pc, "CborDecode", 1, "data", "CBOR binary data is required", null );
		}

		Struct options = args.length > 1 && args[1] != null ? cast.toStruct( args[1] ) : null;

		return call( pc, args[0], options );
	}
}
