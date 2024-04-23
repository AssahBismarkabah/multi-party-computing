package org.bismark.tss;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ThresholdSignatureGenerator {

    public static byte[] generateThresholdSignature(List<AsymmetricCipherKeyPair> keyPairs, String message) {
        int threshold = keyPairs.size() / 2;

        List<BigInteger> partialSignatures = new ArrayList<>();
        for (AsymmetricCipherKeyPair keyPair : keyPairs) {
            AsymmetricKeyParameter privateKeyParams = keyPair.getPrivate();
            BigInteger[] partialSignature = PartialSignatureGenerator.generatePartialSignature(privateKeyParams, message);
            partialSignatures.add(new BigInteger(1, concatenateArrays(partialSignature)));
        }

        BigInteger finalSignature = BigInteger.ZERO;
        for (int i = 0; i < threshold; i++) {
            BigInteger partialSignature = partialSignatures.get(i);
            for (int j = 0; j < threshold; j++) {
                if (i != j) {
                    BigInteger otherPartyShare = partialSignatures.get(j);
                    BigInteger inverse = otherPartyShare.modInverse(((ECPublicKeyParameters) keyPairs.get(j).getPublic()).getParameters().getN());
                    partialSignature = partialSignature.multiply(otherPartyShare.modPow(inverse, ((ECPublicKeyParameters) keyPairs.get(j).getPublic()).getParameters().getN())).mod(((ECPublicKeyParameters) keyPairs.get(j).getPublic()).getParameters().getN());
                }
            }
            finalSignature = finalSignature.add(partialSignature).mod(((ECPublicKeyParameters) keyPairs.get(i).getPublic()).getParameters().getN());
        }

        return finalSignature.toByteArray();
    }

    private static byte[] concatenateArrays(BigInteger[] arrays) {
        int totalLength = 0;
        for (BigInteger array : arrays) {
            totalLength += array.toByteArray().length;
        }
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (BigInteger array : arrays) {
            byte[] byteArray = array.toByteArray();
            System.arraycopy(byteArray, 0, result, offset, byteArray.length);
            offset += byteArray.length;
        }
        return result;
    }
}