package com.digitalsignature;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class DigitalSignature {
public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
	Signature signature = Signature.getInstance("SHA256WithDSA");
	SecureRandom secureRandom = new SecureRandom();
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
	KeyPair keyPair = keyPairGenerator.generateKeyPair();
	

	signature.initSign(keyPair.getPrivate(), secureRandom);
	
	byte[] data = "abcdefghijklmnopqrstuvxyz".getBytes("UTF-8");
	signature.update(data);

	byte[] digitalSignature = signature.sign();
	
	
	Signature signature2 = Signature.getInstance("SHA256WithDSA");

	signature2.initVerify(keyPair.getPublic());
	
	byte[] data2 = "abcdefghijklmnopqrstuvxyz".getBytes("UTF-8");
	signature2.update(data2);

	boolean verified = signature2.verify(digitalSignature);
	System.out.println(verified);

}
}
