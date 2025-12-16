package org.lucee.extension.crypto;

import java.security.cert.X509Certificate;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Parses a PEM-encoded certificate string into a Java X509Certificate object.
 *
 * Usage:
 *   cert = PemToCertificate( pemCertString )
 */
public class PemToCertificate extends BIF {

	private static final long serialVersionUID = 1L;

	public static X509Certificate call( PageContext pc, String pem ) throws PageException {
		try {
			return CryptoUtil.parseCertificate( pem );
		}
		catch ( Exception e ) {
			throw CFMLEngineFactory.getInstance().getCastUtil().toPageException( e );
		}
	}

	@Override
	public Object invoke( PageContext pc, Object[] args ) throws PageException {
		if ( args.length < 1 ) {
			throw CFMLEngineFactory.getInstance().getExceptionUtil()
				.createFunctionException( pc, "PemToCertificate", 1, "pem", "PEM string is required", null );
		}

		String pem = CFMLEngineFactory.getInstance().getCastUtil().toString( args[0] );
		return call( pc, pem );
	}
}
