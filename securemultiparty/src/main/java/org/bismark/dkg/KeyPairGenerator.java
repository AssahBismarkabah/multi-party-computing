package org.bismark.dkg;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class KeyPairGenerator {

    public static List<AsymmetricCipherKeyPair> generateKeyPairs(int numParties, String curveName) {
        List<AsymmetricCipherKeyPair> keyPairs = new ArrayList<>();
        ECParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec(curveName);
        ECDomainParameters domainParams = new ECDomainParameters(curveSpec.getCurve(), curveSpec.getG(), curveSpec.getN(), curveSpec.getH());

        for (int i = 0; i < numParties; i++) {
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
            keyPairGenerator.init(keyGenParams);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
            keyPairs.add(keyPair);
        }

        return keyPairs;
    }
}