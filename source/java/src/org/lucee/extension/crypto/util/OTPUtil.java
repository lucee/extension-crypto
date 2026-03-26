package org.lucee.extension.crypto.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

/**
 * Shared HOTP/TOTP core per RFC 4226 and RFC 6238.
 * Uses standard JCA (javax.crypto.Mac) — no BouncyCastle needed.
 */
public class OTPUtil {

	public static final int DEFAULT_DIGITS = 6;
	public static final int DEFAULT_PERIOD = 30;
	public static final String DEFAULT_ALGORITHM = "SHA1";
	public static final int DEFAULT_WINDOW = 1;
	public static final int DEFAULT_SECRET_LENGTH = 20;

	// Base32 alphabet (RFC 4648)
	private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	/**
	 * Generate an HOTP code (RFC 4226).
	 */
	public static String generateHOTP( byte[] secret, long counter, int digits, String algorithm ) throws Exception {
		String macAlgorithm = toHmacAlgorithm( algorithm );

		// Counter as 8-byte big-endian
		byte[] counterBytes = ByteBuffer.allocate( 8 ).putLong( counter ).array();

		// HMAC
		Mac mac = Mac.getInstance( macAlgorithm );
		mac.init( new SecretKeySpec( secret, macAlgorithm ) );
		byte[] hmac = mac.doFinal( counterBytes );

		// Dynamic truncation (RFC 4226 section 5.4)
		int offset = hmac[hmac.length - 1] & 0x0F;
		int code = ( ( hmac[offset] & 0x7F ) << 24 )
			| ( ( hmac[offset + 1] & 0xFF ) << 16 )
			| ( ( hmac[offset + 2] & 0xFF ) << 8 )
			| ( hmac[offset + 3] & 0xFF );

		int otp = code % (int) Math.pow( 10, digits );

		// Zero-pad to requested digit length
		return String.format( "%0" + digits + "d", otp );
	}

	/**
	 * Get the TOTP counter for a given time.
	 */
	public static long getTimeCounter( long timeSeconds, int period ) {
		return timeSeconds / period;
	}

	/**
	 * Map algorithm name to JCA HMAC algorithm.
	 */
	public static String toHmacAlgorithm( String algorithm ) {
		if ( algorithm == null || algorithm.trim().isEmpty() ) {
			return "HmacSHA1";
		}
		switch ( algorithm.trim().toUpperCase() ) {
			case "SHA1":
			case "HMACSHA1":
				return "HmacSHA1";
			case "SHA256":
			case "HMACSHA256":
				return "HmacSHA256";
			case "SHA512":
			case "HMACSHA512":
				return "HmacSHA512";
			default:
				throw new IllegalArgumentException(
					"Unsupported OTP algorithm: " + algorithm + ". Use SHA1, SHA256, or SHA512" );
		}
	}

	/**
	 * Map algorithm name to otpauth URI algorithm parameter.
	 */
	public static String toOtpauthAlgorithm( String algorithm ) {
		if ( algorithm == null || algorithm.trim().isEmpty() ) {
			return "SHA1";
		}
		switch ( algorithm.trim().toUpperCase() ) {
			case "SHA1":
			case "HMACSHA1":
				return "SHA1";
			case "SHA256":
			case "HMACSHA256":
				return "SHA256";
			case "SHA512":
			case "HMACSHA512":
				return "SHA512";
			default:
				throw new IllegalArgumentException(
					"Unsupported OTP algorithm: " + algorithm + ". Use SHA1, SHA256, or SHA512" );
		}
	}

	/**
	 * Encode bytes to Base32 (RFC 4648, no padding).
	 */
	public static String base32Encode( byte[] data ) {
		StringBuilder sb = new StringBuilder();
		int buffer = 0;
		int bitsLeft = 0;

		for ( byte b : data ) {
			buffer = ( buffer << 8 ) | ( b & 0xFF );
			bitsLeft += 8;
			while ( bitsLeft >= 5 ) {
				bitsLeft -= 5;
				sb.append( BASE32_CHARS.charAt( ( buffer >> bitsLeft ) & 0x1F ) );
			}
		}
		if ( bitsLeft > 0 ) {
			sb.append( BASE32_CHARS.charAt( ( buffer << ( 5 - bitsLeft ) ) & 0x1F ) );
		}

		return sb.toString();
	}

	/**
	 * Decode Base32 string to bytes (RFC 4648, tolerates padding and whitespace).
	 */
	public static byte[] base32Decode( String encoded ) {
		// Strip padding and whitespace
		String clean = encoded.replaceAll( "[\\s=]", "" ).toUpperCase();

		int totalBits = clean.length() * 5;
		byte[] result = new byte[totalBits / 8];
		int buffer = 0;
		int bitsLeft = 0;
		int index = 0;

		for ( int i = 0; i < clean.length(); i++ ) {
			int val = BASE32_CHARS.indexOf( clean.charAt( i ) );
			if ( val < 0 ) {
				throw new IllegalArgumentException( "Invalid Base32 character: " + clean.charAt( i ) );
			}
			buffer = ( buffer << 5 ) | val;
			bitsLeft += 5;
			if ( bitsLeft >= 8 ) {
				bitsLeft -= 8;
				result[index++] = (byte) ( ( buffer >> bitsLeft ) & 0xFF );
			}
		}

		return result;
	}
}
