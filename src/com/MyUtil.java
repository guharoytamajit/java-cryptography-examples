package com;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

public class MyUtil {

	public static String byteArrayToHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}


	public static String byteArrayToBase64String(byte[] b) {
		byte[] encoded = Base64.getEncoder().encode(b);
		return new String(encoded);
	}
	
	public static byte[] base64ToByteArray(String s) {
		return Base64.getDecoder().decode(s);
	}


	
	/*
	   private static KeyPair loadFromPKCS12(String filename, char[] password)
	            throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
	            FileNotFoundException, IOException, UnrecoverableEntryException {
	        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");

	        try (FileInputStream fis = new FileInputStream(filename);) {
	            pkcs12KeyStore.load(fis, password);
	        }

	        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
	        Entry entry = pkcs12KeyStore.getEntry("owlstead", param);
	        if (!(entry instanceof PrivateKeyEntry)) {
	            throw new KeyStoreException("That's not a private key!");
	        }
	        PrivateKeyEntry privKeyEntry = (PrivateKeyEntry) entry;
	        PublicKey publicKey = privKeyEntry.getCertificate().getPublicKey();
	        PrivateKey privateKey = privKeyEntry.getPrivateKey();
	        return new KeyPair(publicKey, privateKey);
	    }

	    private static void storeToPKCS12(
	            String filename, char[] password,
	            KeyPair generatedKeyPair) throws KeyStoreException, IOException,
	            NoSuchAlgorithmException, CertificateException, FileNotFoundException,
	            OperatorCreationException {

	        Certificate selfSignedCertificate = selfSign(generatedKeyPair, "CN=owlstead");

	        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");
	        pkcs12KeyStore.load(null, null);

	        KeyStore.Entry entry = new PrivateKeyEntry(generatedKeyPair.getPrivate(),
	                new Certificate[] { selfSignedCertificate });
	        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);

	        pkcs12KeyStore.setEntry("owlstead", entry, param);

	        try (FileOutputStream fos = new FileOutputStream(filename)) {
	            pkcs12KeyStore.store(fos, password);
	        }
	    }
	    
	    public static Certificate selfSign(KeyPair keyPair, String subjectDN)
	            throws OperatorCreationException, CertificateException, IOException
	    {
	        Provider bcProvider = new BouncyCastleProvider();
	        Security.addProvider(bcProvider);

	        long now = System.currentTimeMillis();
	        Date startDate = new Date(now);

	        X500Name dnName = new X500Name(subjectDN);

	        // Using the current timestamp as the certificate serial number
	        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

	        Calendar calendar = Calendar.getInstance();
	        calendar.setTime(startDate);
	        // 1 Yr validity
	        calendar.add(Calendar.YEAR, 1);

	        Date endDate = calendar.getTime();

	        // Use appropriate signature algorithm based on your keyPair algorithm.
	        String signatureAlgorithm = "SHA256WithRSA";

	        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair
	                .getPublic().getEncoded());

	        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(dnName,
	                certSerialNumber, startDate, endDate, dnName, subjectPublicKeyInfo);

	        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(
	                bcProvider).build(keyPair.getPrivate());

	        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

	        Certificate selfSignedCert = new JcaX509CertificateConverter()
	                .getCertificate(certificateHolder);

	        return selfSignedCert;
	    }*/
}
