package org.bismark.tss;

import java.security.*;
import java.util.Base64;

public class ECDSAExample {

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // Key size
        KeyPair keyPair = keyGen.generateKeyPair();

        // Get private and public keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Create Signature object
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");

        // Initialize Signature object with private key
        ecdsa.initSign(privateKey);

        // Data to be signed
        String data = "Hello, ECDSA!";
        byte[] message = data.getBytes("UTF-8");

        // Update data to be signed
       ecdsa.update(message);

        // Sign the data
        byte[] signature = ecdsa.sign();

        // Print signature
        System.out.println("Signature: " + bytesToHex(signature));
        System.out.println("private key: " + privateKey);
        System.out.println("public key: " + publicKey);


        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature (Base64): " + signatureBase64);


        // Verify signature
        ecdsa.initVerify(publicKey);
        ecdsa.update(message);
        boolean isVerified = ecdsa.verify(signature);

        // Print verification result
        System.out.println("Signature verified: " + isVerified);
    }

    // Helper method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}

