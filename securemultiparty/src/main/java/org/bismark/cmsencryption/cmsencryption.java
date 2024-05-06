package org.bismark.cmsencryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.util.Base64;

public class cmsencryption {
    public static void main(String[] args) throws Exception {

        // Generat key pair for asymmetric encryption
        KeyPair keyPair = AsymmetricEncryption.generateKeyPair();
        SecretKey symmetricKey = KeyGeneration.generateSymmetricKey();

        // Sender encrypts the message using the symmetric key generated
        String plaintext = "Cryptographic Message Syntax!";
        String encryptedMessage = SymmetricEncryption.encrypt(plaintext, (SecretKeySpec) symmetricKey);

        // Sender encrypts the symmetric key using the recipient's public key
        String encryptedKey = AsymmetricEncryption.encrypt(Base64.getEncoder().encodeToString(symmetricKey.getEncoded()), keyPair.getPublic());

        // Receiver decrypts the symmetric key using their private key
        String decryptedKey = AsymmetricEncryption.decrypt(encryptedKey, keyPair.getPrivate());
        byte[] symmetricKeyBytes = Base64.getDecoder().decode(decryptedKey);
        SecretKey decryptedSymmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");

        // Receiver decrypts the message using the decrypted symmetric key
        String decryptedMessage = SymmetricEncryption.decrypt(encryptedMessage, (SecretKeySpec) decryptedSymmetricKey);

        System.out.println("Original message: " + plaintext);
        System.out.println("Encrypted message: " + encryptedMessage);
        System.out.println("Encrypted symmetric key: " + encryptedKey);
        System.out.println("Decrypted symmetric key: " + decryptedKey);
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}
