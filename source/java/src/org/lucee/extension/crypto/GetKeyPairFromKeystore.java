package org.lucee.extension.crypto;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;

/**
 * Extracts a key pair and certificate from a Java keystore (ACF compatible).
 *
 * Usage:
 *   keyPair = GetKeyPairFromKeystore(
 *       keystore = "/path/to/keystore.p12",
 *       keystorePassword = "changeit",
 *       keystoreAlias = "mykey"
 *   )
 */
public class GetKeyPairFromKeystore extends BIF {

	private static final long serialVersionUID = 1L;

	public static Struct call( PageContext pc, String keystorePath, String keystorePassword,
							   String keypairPassword, String alias, String keystoreType ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Auto-detect keystore type if not specified
			if ( keystoreType == null || keystoreType.isEmpty() ) {
				keystoreType = keystorePath.toLowerCase().endsWith( ".p12" ) ||
							   keystorePath.toLowerCase().endsWith( ".pfx" ) ? "PKCS12" : "JKS";
			}

			// Default keypair password to keystore password
			if ( keypairPassword == null || keypairPassword.isEmpty() ) {
				keypairPassword = keystorePassword;
			}

			// Load keystore
			KeyStore ks = KeyStore.getInstance( keystoreType );
			try ( FileInputStream fis = new FileInputStream( keystorePath ) ) {
				ks.load( fis, keystorePassword.toCharArray() );
			}

			// Get private key
			Key key = ks.getKey( alias, keypairPassword.toCharArray() );
			if ( !( key instanceof PrivateKey ) ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Alias '" + alias + "' does not contain a private key"
				);
			}
			PrivateKey privateKey = (PrivateKey) key;

			// Get certificate chain
			Certificate[] chain = ks.getCertificateChain( alias );
			if ( chain == null || chain.length == 0 ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Alias '" + alias + "' does not have a certificate chain"
				);
			}

			X509Certificate cert = (X509Certificate) chain[0];

			// Build result (use PKCS8 format for private key consistency)
			Struct result = eng.getCreationUtil().createStruct();
			result.set( "private", CryptoUtil.toPemPKCS8( privateKey ) );
			result.set( "public", CryptoUtil.toPem( cert.getPublicKey() ) );
			result.set( "certificate", CryptoUtil.toPem( cert ) );

			return result;
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
		CFMLEngine eng = CFMLEngineFactory.getInstance();

		if ( args.length < 4 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "GetKeyPairFromKeystore", 4, "keystoreAlias",
				"keystore, keystorePassword, and keystoreAlias are required", null
			);
		}

		String keystorePath = eng.getCastUtil().toString( args[0] );
		String keystorePassword = eng.getCastUtil().toString( args[1] );
		String keypairPassword = args.length > 2 && args[2] != null ? eng.getCastUtil().toString( args[2] ) : null;
		String alias = eng.getCastUtil().toString( args[3] );
		String keystoreType = args.length > 4 && args[4] != null ? eng.getCastUtil().toString( args[4] ) : null;

		return call( pc, keystorePath, keystorePassword, keypairPassword, alias, keystoreType );
	}
}
