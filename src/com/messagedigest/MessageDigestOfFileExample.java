package com.messagedigest;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.MyUtil;

public class MessageDigestOfFileExample {
public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
FileInputStream inputStream = new FileInputStream("pattern.pptx");

MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
byte[] data      = new byte[1024];
int    bytesRead = inputStream.read(data);
while(bytesRead != -1) {
	  
	messageDigest.update(data,0,bytesRead);
	  bytesRead = inputStream.read(data);
	  //here we are finding the digest of file content ,not any of its metadata
	}
	inputStream.close();

//other algorithms: MD2 MD5 SHA-1 SHA-256 SHA-384 SHA-512
	

	byte[] digest = messageDigest.digest();
	System.out.println(MyUtil.byteArrayToHexString(digest));
	// we can verify the same with:  > openssl sha512 pattern.pptx


}
}
