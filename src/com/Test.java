package com;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Test {
	public static void main(String[] args) throws Exception {
		createKeyStore();
	}
	public static KeyStore createKeyStore() throws Exception {
	    File file = new File("keystore");
	    KeyStore keyStore = KeyStore.getInstance("JCEKS");
	    if (file.exists()) {
	        // if exists, load
	        keyStore.load(new FileInputStream(file), "123456".toCharArray());
	    } else {
	        // if not exists, create
	        keyStore.load(null, null);
	        
			// Creating the KeyStore.ProtectionParameter object
			KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(
					"123456".toCharArray());
			// Creating SecretKey objec
			SecretKey mySecretKey = new SecretKeySpec(
					new String("secret").getBytes(), "DSA");
			// Creating SecretKeyEntry object
			KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(
					mySecretKey);
//			keyStore.setEntry("secretKeyAlias", secretKeyEntry, protectionParam);
	        keyStore.store(new FileOutputStream(file), "123456".toCharArray());
	    }
	    return keyStore;
	}
}
