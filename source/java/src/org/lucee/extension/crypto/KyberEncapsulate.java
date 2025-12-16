package org.lucee.extension.crypto;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.lucee.extension.crypto.util.CryptoUtil;

import lucee.loader.engine.CFMLEngine;
import lucee.loader.engine.CFMLEngineFactory;
import lucee.runtime.PageContext;
import lucee.runtime.exp.PageException;
import lucee.runtime.ext.function.BIF;
import lucee.runtime.type.Struct;

/**
 * Performs Kyber key encapsulation to create a shared secret.
 *
 * Kyber (ML-KEM) is a post-quantum key encapsulation mechanism.
 * Use this to establish a shared secret with someone who has a Kyber public key.
 *
 * Usage:
 *   result = KyberEncapsulate( publicKey )
 *   // result.sharedSecret = binary (use for symmetric encryption)
 *   // result.ciphertext = string (send to key owner)
 */
public class KyberEncapsulate extends BIF {

	private static final long serialVersionUID = 1L;

	public static Struct call( PageContext pc, Object publicKey ) throws PageException {
		try {
			CryptoUtil.ensureProvider();
			CFMLEngine eng = CFMLEngineFactory.getInstance();

			// Parse public key
			PublicKey pubKey;
			if ( publicKey instanceof PublicKey ) {
				pubKey = (PublicKey) publicKey;
			}
			else {
				String pemStr = eng.getCastUtil().toString( publicKey );
				pubKey = CryptoUtil.parsePublicKey( pemStr );
			}

			// Verify it's an ML-KEM (Kyber) key
			String keyAlg = pubKey.getAlgorithm().toUpperCase();
			if ( !keyAlg.startsWith( "ML-KEM" ) ) {
				throw eng.getExceptionUtil().createApplicationException(
					"Public key must be an ML-KEM (Kyber) key, got: " + pubKey.getAlgorithm() );
			}

			// Perform encapsulation using the key's specific algorithm (e.g., ML-KEM-768)
			KeyGenerator keyGen = KeyGenerator.getInstance( pubKey.getAlgorithm(), "BC" );
			keyGen.init( new KEMGenerateSpec( pubKey, "AES" ), new SecureRandom() );
			SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation) keyGen.generateKey();

			// Build result
			Struct result = eng.getCreationUtil().createStruct();
			result.set( "sharedSecret", secretKey.getEncoded() );
			result.set( "ciphertext", Base64.getEncoder().encodeToString( secretKey.getEncapsulation() ) );

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

		if ( args.length < 1 ) {
			throw eng.getExceptionUtil().createFunctionException(
				pc, "KyberEncapsulate", 1, "publicKey", "publicKey is required", null
			);
		}

		return call( pc, args[0] );
	}
}
