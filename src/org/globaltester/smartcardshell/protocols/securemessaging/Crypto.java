package org.globaltester.smartcardshell.protocols.securemessaging;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class Crypto {

	public static byte[] nullIV = {0,0,0,0,0,0,0,0};
	private static IvParameterSpec ivSpec = null;
	
	public static int BLOCKLENGTH = 8;
	
	
	
	public static byte[] computeCryptogram(byte[] plainText, SecretKey key, int mode){
		Cipher c = null;
		Cipher c1 = null;
		Cipher c2 = null;
		byte[] y = null;
		
		
		ivSpec = new IvParameterSpec(nullIV);
		
		try {
			c1 = Cipher.getInstance("DES/CBC/NoPadding");
			c2 = Cipher.getInstance("DESede/CBC/NoPadding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		/*
		 * Get the cipher
		 */
		if (key.getEncoded().length == 8) {
			c = c1;
		} else {
			c = c2;
		}
		/*
		 * do the encryption
		 */
		try {
			c.init(mode, key, ivSpec);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			y = c.doFinal(plainText);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return y;
		
	}
	
	public static byte[] computeChecksum(byte[] plaintext, SecretKey skenc, boolean usessc) {

		if (plaintext.length == 0)
			return new byte[0];

		SecretKey key = null;
		Cipher c = null;
		Cipher cc = null;
		byte[] y = null;
		byte[] key1 = new byte[8];
		byte[] key2 = new byte[8];
		SecretKey k1 = null;
		SecretKey k2 = null;
		/*
		 * Get the key and divide it into 3 single DES keys if DES 3 is
		 * referenced
		 */

		key = skenc;
		
		if (key.getEncoded().length == 8) {
			System.arraycopy(key.getEncoded(), 0, key1, 0, 8);
			System.arraycopy(key.getEncoded(), 0, key2, 0, 8);
		} else {
			System.arraycopy(key.getEncoded(), 0, key1, 0, 8);
			System.arraycopy(key.getEncoded(), 8, key2, 0, 8);
		}
		try {
			k1 = SecretKeyFactory
					.getInstance("DES").generateSecret(new DESKeySpec(key1)); //$NON-NLS-1$
			k2 = SecretKeyFactory
					.getInstance("DES").generateSecret(new DESKeySpec(key2)); //$NON-NLS-1$

		} catch (Exception e) {
			e.printStackTrace();
		}
		/*
		 * Get the cipher object
		 */
		try {
			c = Cipher.getInstance("DES/CBC/NoPadding"); //$NON-NLS-1$
			/*
			 * Cipher for the last round
			 */
			cc = Cipher.getInstance("DES/ECB/NoPadding"); //$NON-NLS-1$
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		/*
		 * do the encryption
		 */
		try {
			/*
			 * first increase the SSC before each verification if session key is
			 * applied
			 */
			//if (keyid == 0xFF || keyid == 0xFD)
			if (key.getAlgorithm().equals("DESede"))
				//SendSequenceCounter.increase();
			/*
			 * Do the first round with the NULL ICV and the SSC
			 */
			ivSpec = new IvParameterSpec(nullIV);
			c.init(Cipher.ENCRYPT_MODE, k1, ivSpec);
			if (usessc) {
				//c.update(SendSequenceCounter.getEncoded());
			}
			/*
			 * get cryptogram in CBC mode
			 */
			y = c.doFinal(plaintext);
			int offset = Math.max(0, y.length - BLOCKLENGTH);
			if (offset >= 0) {
				cc.init(Cipher.DECRYPT_MODE, k2);
				y = cc.doFinal(y, offset, BLOCKLENGTH);
				cc.init(Cipher.ENCRYPT_MODE, k1);
				y = cc.doFinal(y, 0, BLOCKLENGTH);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return y;
	}

	
	public static byte[] computeMAC(byte[] plainText, SecretKey key, String algorithm){
		Mac mac = null;

		try {
			mac = Mac.getInstance(algorithm,
					BouncyCastleProvider.PROVIDER_NAME);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			mac.init(key);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		mac.update(plainText);
		return mac.doFinal();
		
	}
	
	public static byte[] computeMAC(byte[] plainText, SecretKey key) {
		return computeMAC(plainText, key, "ISO9797ALG3WITHISO7816-4PADDING");
	}

	
	
	public static SecretKey deriveKey(byte[] keySeed, byte mode){
		MessageDigest shaDigest = null;
		try {
			shaDigest = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException ex) {
			System.err.println(ex);
		}
		shaDigest.update(keySeed);
		byte[] c = { 0x00, 0x00, 0x00, (byte) mode };
		shaDigest.update(c);
		byte[] hash = shaDigest.digest();
		byte[] key = new byte[24];
		System.arraycopy(hash, 0, key, 0, 8);
		System.arraycopy(hash, 8, key, 8, 8);
		System.arraycopy(hash, 0, key, 16, 8);
				
		SecretKeyFactory desKeyFactory = null;
		try {
			desKeyFactory = SecretKeyFactory.getInstance("DESede");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			return desKeyFactory.generateSecret(new DESedeKeySpec(key));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	


	
}
