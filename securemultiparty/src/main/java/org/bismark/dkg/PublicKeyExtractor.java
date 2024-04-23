package org.bismark.dkg;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.util.ArrayList;
import java.util.List;

//extractPublicKeys method to extract the public keys from the generated key pairs
public class PublicKeyExtractor {

    public static List<ECPublicKeyParameters> extractPublicKeys(List<AsymmetricCipherKeyPair> keyPairs) {
        List<ECPublicKeyParameters> publicKeys = new ArrayList<>();

        for (AsymmetricCipherKeyPair keyPair : keyPairs) {
            ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) keyPair.getPublic();
            publicKeys.add(publicKeyParams);
        }

        return publicKeys;
    }
}
