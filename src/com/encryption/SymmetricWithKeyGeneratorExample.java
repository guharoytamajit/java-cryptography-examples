package com.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import java.security.Key;
import java.security.SecureRandom;

public class SymmetricWithKeyGeneratorExample {
   public static void main(String args[]) throws Exception{
      //Creating a KeyGenerator object
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      
      //Creating a SecureRandom object
      SecureRandom secRandom = new SecureRandom();
      
      //Initializing the KeyGenerator
      keyGen.init(secRandom);
      
      //Creating/Generating a key
      Key key = keyGen.generateKey();
      
      System.out.println(key);      
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");      
      cipher.init(cipher.ENCRYPT_MODE, key);      

      String msg = new String("Hi how are you");
      System.out.println("Original: "+msg);
      byte[] bytes = cipher.doFinal(msg.getBytes()); 
      System.out.println("Encrypted: "+new String(bytes));
      cipher.init(cipher.DECRYPT_MODE, key); 
      System.out.println("Decrypted: "+new String(cipher.doFinal(bytes)));      
   }
}
