package org.telegram.messenger;

import com.google.android.exoplayer2.util.Log;

import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AnamorphicMessagingHelper {
    // Class private variables
    private static final String SECRET_KEY
            = "my_super_secret_key_ho_ho_ho";

    private static final String SALT = "ssshhhhhhhhhhh!!!!";

    // This method use to encrypt to string
    public static byte[] encrypt(byte[] input, byte[] iv, boolean exception)
    {
        try {
            IvParameterSpec ivspec
                    = new IvParameterSpec(iv);

            // Create SecretKeyFactory object
            SecretKeyFactory factory
                    = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(
                    SECRET_KEY.toCharArray(), SALT.getBytes(),
                    65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(
                    tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance(
                    "AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey,
                    ivspec);

            /*
                TODO: check if some characters in the anamorphic message take up more bytes than others.
                If so, we need a better way to validate the input
            */
            // Return encrypted string
            return cipher.doFinal(input);
        }
        catch (Exception e) {
            if (exception) {
                Log.e("MyTest", String.format("Error while encrypting: %s", e));
            }
        }
        return null;
    }

    // This method use to decrypt to string
    public static byte[] decrypt(byte[] strToDecrypt, byte[] iv, boolean usePadding, boolean exception)
    {
        try {
            // Create IvParameterSpec object and assign with
            // constructor
            IvParameterSpec ivspec
                    = new IvParameterSpec(iv);

            // Create SecretKeyFactory Object
            SecretKeyFactory factory
                    = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(
                    SECRET_KEY.toCharArray(), SALT.getBytes(),
                    65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(
                    tmp.getEncoded(), "AES");

            String transformation = usePadding ? "AES/CBC/PKCS5PADDING" : "AES/CBC/NoPadding";

            // TODO: try to decrypt a padded string with NoPadding to check if the "PKCS5Padding" is actually PKCS#7

            Cipher cipher = Cipher.getInstance(
                    transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey,
                    ivspec);
            // Return decrypted string
            return cipher.doFinal(strToDecrypt);
        }
        catch (Exception e) {
            if (exception) {
                Log.e("MyTest", String.format("Error while decrypting: %s", e));
            }
        }
        return null;
    }

    /**
     * Try to decrypt with and without padding
     * @param b
     * @param iv
     * @return
     */
    public static byte[] tryDecrypt(byte[] b, byte[] iv) {
        byte[] arr = decrypt(b, iv, true, true);
        if (arr == null) {
            arr = decrypt(b, iv, false, true);
        }
        return arr;
    }
}
