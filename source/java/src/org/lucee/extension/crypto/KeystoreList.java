package org.lucee.extension.crypto;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Array;
import lucee.runtime.util.Cast;

/**
 * Lists all aliases in a Java keystore.
 *
 * Usage:
 *   aliases = KeystoreList( keystore="/path/to/keystore.p12", keystorePassword="changeit" )
 */
public class KeystoreList extends BIF {

	private static final long serialVersionUID = 1L;

	public static Array call( PageContext pc, String keystorePath, String keystorePassword, String keystoreType )
			throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Auto-detect keystore type if not specified
			if ( keystoreType == null || keystoreType.isEmpty() ) {
				keystoreType = keystorePath.toLowerCase().endsWith( ".p12" ) ||
							   keystorePath.toLowerCase().endsWith( ".pfx" ) ? "PKCS12" : "JKS";
			}

			// Load keystore
			KeyStore ks = KeyStore.getInstance( keystoreType );
			try ( FileInputStream fis = new FileInputStream( keystorePath ) ) {
				ks.load( fis, keystorePassword.toCharArray() );
			}

			// Get all aliases
			Array result = eng.getCreationUtil().createArray();
			Enumeration<String> aliases = ks.aliases();
			while ( aliases.hasMoreElements() ) {
				result.append( aliases.nextElement() );
			}

			return result;
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		CFMLEngine eng = CFMLEngineFactory.getInstance();
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "KeystoreList", 2, "keystorePassword",
				"keystore and keystorePassword are required", null
			);
		}

		String keystorePath = cast.toString( args[0] );
		String keystorePassword = cast.toString( args[1] );
		String keystoreType = args.length > 2 && args[2] != null ? cast.toString( args[2] ) : null;

		return call( pc, keystorePath, keystorePassword, keystoreType );
	}
}
