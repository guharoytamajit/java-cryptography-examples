package com.messagedigest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.MyUtil;

public class MessageDigestExample {
public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
	byte[] data1 = "hello".getBytes("UTF-8");
	byte[] data2 = "world".getBytes("UTF-8");

	MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
//other algorithms: MD2 MD5 SHA-1 SHA-256 SHA-384 SHA-512
	messageDigest.update(data1);
	messageDigest.update(data2);

	byte[] digest = messageDigest.digest();
	System.out.println(MyUtil.byteArrayToHexString(digest));
	// we can verify the same with:  >echo -n "helloworlds" | openssl sha512

}
}
