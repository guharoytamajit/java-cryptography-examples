package com.keystore;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreExample {
	public static void main(String[] args) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException {
//		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		 KeyStore keyStore = KeyStore.getInstance("JCEKS");
//		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] keyStorePassword = "123456".toCharArray();
		keyStore.load(null, keyStorePassword);// we dont have any existing ks so null
												
		// If want to use existing keystore we can load it as follow
		/*
		 * try(InputStream keyStoreData = new FileInputStream("keystore.ks")){
		 * keyStore.load(keyStoreData, keyStorePassword); }
		 */

		// Creating the KeyStore.ProtectionParameter object
		KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(
				keyStorePassword);
		// Creating SecretKey objec
		String keyPass = "secret";
		String keyAlias = "secretKeyAlias";
		SecretKey mySecretKey = new SecretKeySpec(
				new String(keyPass).getBytes(), "DSA");
		// Creating SecretKeyEntry object
		KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(
				mySecretKey);
		keyStore.setEntry(keyAlias, secretKeyEntry, protectionParam);

		java.io.FileOutputStream fos = null;
		fos = new java.io.FileOutputStream("keystore.ks");
		keyStore.store(fos, keyStorePassword);
		fos.flush();fos.close();
		
		System.out.println("Saved and retrieved keys are same: "+mySecretKey.equals(keyStore.getKey(keyAlias, keyStorePassword)));
		
		
		Enumeration<String> aliases = keyStore.aliases();
		System.out.println("Following entries found in keystore:");
		while(aliases.hasMoreElements()){
			System.out.println(aliases.nextElement());
		}
		System.out.println("View keytool entries with:\n > keytool -list -v -storetype JCEKS  -keystore keystore.ks --alias secretKeyAlias");

	}
}
