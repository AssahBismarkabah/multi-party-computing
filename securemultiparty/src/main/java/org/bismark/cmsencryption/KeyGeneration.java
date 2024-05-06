package org.bismark.cmsencryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class KeyGeneration {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}