package com.encryption;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricExample {
	public static void main(String[] args) throws NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException,
			InvalidKeyException {

		byte[] setretKey = "secret!!!!!!!!!!".getBytes();// this key has to be
															// 16 chars long or
															// alternative way
															// around you can
															// take first 16
															// chars of sha1 of
															// secretkey of any
															// length as shown
															// below

		// byte[] setretKey
		// =Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest("any-length-secret".getBytes("UTF-8")),16);

		SecretKey secretKey = new SecretKeySpec(setretKey, "AES");

		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		String encrypted = Base64.getEncoder().encodeToString(
				cipher.doFinal("hello".getBytes("UTF-8")));

		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		System.out.println(new String(cipher.doFinal(Base64.getDecoder()
				.decode(encrypted))));

	}
}
