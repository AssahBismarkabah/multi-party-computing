package org.bismark.tss;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.math.BigInteger;

public class PartialSignatureGenerator {

    public static BigInteger[] generatePartialSignature(AsymmetricKeyParameter privateKey, String message) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new ECPrivateKeyParameters(((ECPrivateKeyParameters) privateKey).getD(), ((ECPrivateKeyParameters) privateKey).getParameters()));
        byte[] messageBytes = message.getBytes();
        return signer.generateSignature(messageBytes);
    }
}
