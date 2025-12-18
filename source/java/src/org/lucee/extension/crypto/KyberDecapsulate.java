package org.lucee.extension.crypto;

import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.util.Cast;

/**
 * Performs Kyber key decapsulation to recover a shared secret.
 *
 * Kyber (ML-KEM) is a post-quantum key encapsulation mechanism.
 * Use this to recover the shared secret from a ciphertext created by KyberEncapsulate.
 *
 * Usage:
 *   sharedSecret = KyberDecapsulate( privateKey, ciphertext )
 *   // sharedSecret = binary (same as sender's sharedSecret)
 */
public class KyberDecapsulate extends BIF {

	private static final long serialVersionUID = 1L;

	public static Object call( PageContext pc, Object privateKey, String ciphertext ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Parse private key
			PrivateKey privKey;
			if ( privateKey instanceof PrivateKey ) {
				privKey = (PrivateKey) privateKey;
			}
			else {
				String pemStr = eng.getCastUtil().toString( privateKey );
				privKey = CryptoUtil.parsePrivateKey( pemStr );
			}

			// Verify it's an ML-KEM (Kyber) key
			String keyAlg = privKey.getAlgorithm().toUpperCase();
			if ( !keyAlg.startsWith( "ML-KEM" ) ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Private key must be an ML-KEM (Kyber) key, got: " + privKey.getAlgorithm() );
			}

			// Decode ciphertext
			byte[] encapsulation = Base64.getDecoder().decode( ciphertext.trim() );

			// Perform decapsulation using the key's specific algorithm (e.g., ML-KEM-768)
			KeyGenerator keyGen = KeyGenerator.getInstance( privKey.getAlgorithm(), "BC" );
			keyGen.init( new KEMExtractSpec( privKey, encapsulation, "AES" ) );
			SecretKey sharedSecret = keyGen.generateKey();

			return sharedSecret.getEncoded();
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
		Cast cast = eng.getCastUtil();

		if ( args.length < 2 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "KyberDecapsulate", 2, "ciphertext",
				"privateKey and ciphertext are required", null
			);
		}

		Object privateKey = args[0];
		String ciphertext = cast.toString( args[1] );

		return call( pc, privateKey, ciphertext );
	}
}
