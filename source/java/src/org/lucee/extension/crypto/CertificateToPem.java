package org.lucee.extension.crypto;

import java.security.cert.X509Certificate;

import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;

/**
 * Converts a Java X509Certificate to PEM format.
 *
 * Usage:
 *   pem = CertificateToPem( certObject )
 */
public class CertificateToPem extends BIF {

	private static final long serialVersionUID = 1L;

	public static String call( PageContext pc, Object certificate ) throws PageException {
		try {
			X509Certificate cert;

			if ( certificate instanceof X509Certificate ) {
				cert = (X509Certificate) certificate;
			}
			else if ( certificate instanceof String ) {
				// If it's already a string, try to parse and re-export (normalizes format)
				cert = CryptoUtil.parseCertificate( (String) certificate );
			}
			else {
				throw CFMLEngineFactory.getInstance().getExceptionUtil()
					.createApplicationException( "Certificate must be an X509Certificate object or PEM string" );
			}

			return CryptoUtil.toPem( cert );
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
				.createFunctionException( pc, "CertificateToPem", 1, "certificate", "Certificate is required", null );
		}

		return call( pc, args[0] );
	}
}
