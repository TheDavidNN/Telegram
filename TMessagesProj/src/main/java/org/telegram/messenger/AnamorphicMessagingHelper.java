package org.telegram.messenger;

import com.google.android.exoplayer2.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.annotation.Nonnull;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AnamorphicMessagingHelper {
    // Class private variables
    private static final int BLOCK_SIZE = 16;
    private static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";

    private static final String SALT = "ssshhhhhhhhhhh!!!!";

    /**
     *
     * @param inputLen The length of the message, not including padding or the prepended number of blocks
     * @return The number of 16-byte blocks needed to encrypt and format a message of length inputLen
     */
    private static byte getPaddingBlocksNeeded(int inputLen) {
        byte blocksNeeded;

        if (inputLen <= 14) {
            /*
            in the first block, there is room for:
            - 1 byte specifying the number of blocks
            - max 14 bytes of message data
            - min 1 padding byte
             */
            blocksNeeded = 1;
        } else if (inputLen <= 29) {
            /*
            in the second block, there is room for:
            - max 15 bytes of message data (plus 14 from the first block)
            - min 1 padding byte
             */
            blocksNeeded = 2;
        } else {
            int remainingBytes = inputLen - 29;

            // amount of padding needed, excluding the mandatory 2 bytes
            int extraPaddingNeeded = remainingBytes % BLOCK_SIZE == 0 ? 0 : BLOCK_SIZE - (remainingBytes % BLOCK_SIZE);

            // how many blocks needed after the first two
            byte extraBlocksNeeded = (byte) ((remainingBytes + extraPaddingNeeded) / BLOCK_SIZE);

            blocksNeeded = (byte) (2 + extraBlocksNeeded);
        }

        return blocksNeeded;
    }

    public static boolean validAMsg(String aMsg, int paddingLen) {
        int messageLen = aMsg.getBytes(StandardCharsets.UTF_8).length;
        int paddingBytesNeeded = getPaddingBlocksNeeded(messageLen) * BLOCK_SIZE;

        return paddingBytesNeeded <= paddingLen;
    }

    private static byte[] prepend(byte b, byte[] arr) {
        byte[] tmp = new byte[arr.length + 1];

        tmp[0] = b;
        System.arraycopy(arr, 0, tmp, 1, arr.length);

        return tmp;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] arr = new byte[a.length + b.length];

        System.arraycopy(a, 0, arr, 0, a.length);
        System.arraycopy(b, 0, arr, a.length, b.length);

        return arr;
    }

    private static byte[] aesCbcEnc(byte[] plaintext, byte[] iv) throws GeneralSecurityException {
        try {
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // Create SecretKeyFactory object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

            /*
                TODO: check if some characters in the anamorphic message take up more bytes than others.
                If so, we need a better way to validate the input
            */

            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            Log.e("MyTest", String.format("Error while encrypting: %s", e));
            throw e;
        }
    }

    private static byte[] aesCbcDec(byte[] strToDecrypt, byte[] iv, boolean usePadding) throws GeneralSecurityException {
        try {
            // Create IvParameterSpec object and assign with
            // constructor
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // Create SecretKeyFactory Object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            String transformation = usePadding ? "AES/CBC/PKCS5PADDING" : "AES/CBC/NoPadding";

            // TODO: try to decrypt a padded string with NoPadding to check if the "PKCS5Padding" is actually PKCS#7

            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            // Return decrypted string
            return cipher.doFinal(strToDecrypt);
        } catch (Exception e) {
            Log.e("MyTest", String.format("Error while decrypting: %s", e));
            throw e;
        }
    }

    public static AnamorphicMessage encrypt(String input, boolean exception) throws Exception {
        // TODO: use random IV
        byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] plaintext = input.getBytes(StandardCharsets.UTF_8);
        byte[] formattedCiphertext = null;

        byte numBlocksNeeded = getPaddingBlocksNeeded(plaintext.length);

        byte[] prependedPlaintext = prepend(numBlocksNeeded, plaintext);

        if (numBlocksNeeded == 1) {
            formattedCiphertext = aesCbcEnc(prependedPlaintext, iv);
        } else if (numBlocksNeeded > 1) {
            byte[] firstPlaintextBlock = Arrays.copyOfRange(prependedPlaintext, 0, 15); // leaves one byte for padding
            byte[] firstCiphertextBlock = aesCbcEnc(firstPlaintextBlock, iv);

            byte[] remainingPlaintext = Arrays.copyOfRange(prependedPlaintext, 15, prependedPlaintext.length);
            byte[] remainingCiphertext = aesCbcEnc(remainingPlaintext, iv);

            if (firstCiphertextBlock != null && remainingCiphertext != null) {
                formattedCiphertext = concat(firstCiphertextBlock, remainingCiphertext);
            } else if (firstCiphertextBlock == null) {

            } else if (remainingCiphertext == null) {

            }
        } else {
            Log.e("MyTest", String.format("Error: numBlocksNeeded should be positive, but it is: %d", numBlocksNeeded));
            if (exception) {
                throw new RuntimeException(String.format("Illegal value calculated for numBlocksNeeded! Expected positive integer, got %d", numBlocksNeeded));
            }
        }

        return new AnamorphicMessage(iv, formattedCiphertext);
    }

    /**
     *
     * @return null if the plaintext does not contain a covert message. Otherwise, returns the covert message with the formatting removed
     */
    public static String tryDecrypt(byte[] random_bytes, byte[] padding) {
        byte[] iv = new byte[BLOCK_SIZE];
        System.arraycopy(random_bytes, 0, iv, 0, 15);
        iv[15] = padding[0];

        byte[] firstBlockEncrypted = Arrays.copyOfRange(padding, 1, 17);
        byte[] firstBlockDecrypted;

        try {
            firstBlockDecrypted = aesCbcDec(firstBlockEncrypted, iv, true);
        } catch (GeneralSecurityException e) {
            return null;
        }

        android.util.Log.d("MyTest", "First block decrypted successfully");

        // get the number of blocks encrypted
        byte n = firstBlockDecrypted[0];
        byte[] firstBlockSerializedString = Arrays.copyOfRange(firstBlockDecrypted, 1, firstBlockDecrypted.length);
        String firstBlockString = new String(firstBlockSerializedString);

        android.util.Log.d("MyTest", "A");

        if (n == 1) {
            return firstBlockString;
        } else if (n > 1) {
            android.util.Log.d("MyTest", "B");

            int numRemainingCiphertextBytes = (n - 1) * BLOCK_SIZE;

            // if the number of bytes needed for the message is greater than the number given, return null
            // we minus one from the length to compensate for the one byte of padding used for the IV
            if (numRemainingCiphertextBytes + 16 > padding.length - 1) {
                Log.e("MyTest", String.format(
                        "First block decrypted successfully. It specified a total of %d blocks, but the padding only contains %d bytes usable for ciphertext", padding.length-1,
                        n)
                );
                return null;
            }

            byte[] remainingCiphertext = Arrays.copyOfRange(padding, 17, 17 + numRemainingCiphertextBytes);

            android.util.Log.d("MyTest", "C");
            byte[] remainingPlaintext;

            try {
                remainingPlaintext = AnamorphicMessagingHelper.aesCbcDec(remainingCiphertext, iv, true);
            } catch (GeneralSecurityException e) {
                Log.e("MyTest", String.format(
                        "First block decrypted successfully. It specified a total of %d blocks, but failed to decrypt later block",
                        n)
                );
                return null;
            }

            android.util.Log.d("MyTest", "D");

            String remainingBlocksString = new String(remainingPlaintext);

            return firstBlockString + remainingBlocksString;
        } else {
            Log.e("MyTest", String.format("Expected positive number of blocks, received %d", n));
            return null;
        }
    }
}
