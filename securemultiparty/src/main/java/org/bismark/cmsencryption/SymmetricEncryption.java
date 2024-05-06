package org.bismark.cmsencryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class SymmetricEncryption {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encrypt(String plaintext, SecretKeySpec secretKeySpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.toBase64String(ciphertext);
    }

    public static String decrypt(String ciphertext, SecretKeySpec secretKeySpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decrypted = cipher.doFinal(Base64.decode(ciphertext));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
