package org.bismark.privacy;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

public class PublicKeyDerivation {

    public static ECPublicKeyParameters derivePublicKey(List<ECPublicKeyParameters> publicKeys, String derivationPath) {
        ECNamedCurveParameterSpec curveParams = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPublicKeyParameters derivedPublicKey = publicKeys.get(0); // Start with the first public key

        String[] pathSegments = derivationPath.split("/");

        for (String segment : pathSegments) {
            int index = Integer.parseInt(segment);
            ECPublicKeyParameters publicKey = publicKeys.get(index);
            BigInteger privateKey = derivedPublicKey.getParameters().getH().multiply(derivedPublicKey.getQ().getAffineXCoord().toBigInteger());
            BigInteger childPrivateKey = privateKey.add(publicKey.getParameters().getH().multiply(publicKey.getQ().getAffineXCoord().toBigInteger())).mod(curveParams.getN());
            ECPoint childQ = curveParams.getG().multiply(childPrivateKey);
            derivedPublicKey = new ECPublicKeyParameters(childQ, derivedPublicKey.getParameters());
        }

        return derivedPublicKey;
    }
}