package org.bismark;

import org.bismark.dkg.KeyPairGenerator;
import org.bismark.dkg.PublicKeyExtractor;
import org.bismark.privacy.PublicKeyDerivation;
import org.bismark.tss.ThresholdSignatureGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.util.Arrays;
import java.util.List;

public class SecureMultipartyComputation {

    public static void main(String[] args) {
        // Distributed Key Generation (DKG)

        // we're generating a list of asymmetric key pairs using the KeyPairGenerator module.
        List<AsymmetricCipherKeyPair> keyPairs = KeyPairGenerator.generateKeyPairs(3, "secp256r1");

        //extracting the public keys from the generated key pairs using the PublicKeyExtractor module.
        List<ECPublicKeyParameters> publicKeys = PublicKeyExtractor.extractPublicKeys(keyPairs);

        // Threshold Signature Scheme (TSS)
        //  Here, we're using the ThresholdSignatureGenerator module to generate a threshold signature.
        String message = "Secure, Multiparty!";
        byte[] signature = ThresholdSignatureGenerator.generateThresholdSignature(keyPairs, message);

        // Privacy
        // PublicKeyDerivation module to derive a public key.
        // pass in the list of public keys and a derivation path ("m/0/1/2") to derive the desired public key
        ECPublicKeyParameters derivedPublicKey = PublicKeyDerivation.derivePublicKey(publicKeys, "0/1/2");

        System.out.println("Generated Signature: " + Arrays.toString(signature));
        System.out.println("Derived Public Key: " + derivedPublicKey);
    }
}