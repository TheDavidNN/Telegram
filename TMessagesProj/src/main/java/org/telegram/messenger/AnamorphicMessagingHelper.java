package org.telegram.messenger;

import com.google.android.exoplayer2.util.Log;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

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

    private static SecretKeySpec secretKey;

    private static final byte[] AMSG_PREFIX = {0, 0, 0, 0};

    static {
        try {
            String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
            String SALT = "ssshhhhhhhhhhh!!!!";

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            Log.e("MyTest", String.format("Error while encrypting: %s", e));
            throw new RuntimeException(e);
        }

    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] arr = new byte[a.length + b.length];

        System.arraycopy(a, 0, arr, 0, a.length);
        System.arraycopy(b, 0, arr, a.length, b.length);

        return arr;
    }

    private static byte[] createPlaintext(byte[] prefix, short n, byte[] plaintext) {
        byte[] arr = new byte[prefix.length + 2 + plaintext.length];

        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.putShort(n);
        byte[] byteArray = buffer.array();

        System.arraycopy(prefix, 0, arr, 0, prefix.length);
        System.arraycopy(byteArray, 0, arr, prefix.length, byteArray.length);
        System.arraycopy(plaintext, 0, arr, prefix.length + byteArray.length, plaintext.length);

        return arr;
    }

    public static AnamorphicMessage tryEncrypt(String input, int paddingLength) {
        // IV needs to be 16 bytes

        // If the padding is at most 1024 bytes, that is 64 blocks of size 16
        // Since 1 byte of padding is used for IV, we have a max of 63 ciphertext blocks in the padding
        // We use a 15-byte nonce and a 1-byte counter.
        // A nonce of 15-bytes (120 bits) means that we are likely to encounter a collision after 2^120 messages
        // A counter of 1 byte (8 bits) means that we can only safely encrypt 2^8 (256) blocks
        // This is fine since we expect at most 63, if we increased the padding to the max

        byte[] plaintext = input.getBytes(StandardCharsets.UTF_8);

        if (paddingLength < AMSG_PREFIX.length + 2 + plaintext.length) {
            // not enough padding
            Log.e("MyTest",
                    String.format(
                            "Plaintext of length %d is too long for padding of length %d",
                            plaintext.length,
                            paddingLength
                    )
            );
            return null;
        }

        short n = (short) plaintext.length;

        plaintext = createPlaintext(AMSG_PREFIX, n, plaintext);

        Log.d("MyTest", String.format(
                "plaintext: %s",
                Arrays.toString(plaintext)
        ));

        byte[] nonce = new byte[15];
        Utilities.random.nextBytes(nonce);

        byte[] iv = new byte[16];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] ciphertext = cipher.doFinal(plaintext);

            Log.d("MyTest", String.format(
                    "Ciphertext prefix and counter: %s",
                    Arrays.toString(Arrays.copyOf(ciphertext, AMSG_PREFIX.length + 2))
            ));

            Log.d("MyTest", "-------------------------------\nDecrypt own message\n-------------------------------");

            tryDecrypt(nonce, ciphertext);

            return new AnamorphicMessage(nonce, ciphertext);
        } catch (NoSuchPaddingException |
                 InvalidKeyException |
                 BadPaddingException |
                 InvalidAlgorithmParameterException |
                 NoSuchAlgorithmException |
                 IllegalBlockSizeException e) {
            Log.e("MyTest", e.getMessage());
            return null;
        }
    }

    /**
     *
     */
    public static String tryDecrypt(byte[] random_bytes, byte[] padding) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        byte[] iv = new byte[16];
        byte[] iv2 = new byte[16];

        System.arraycopy(random_bytes, 0, iv, 0, random_bytes.length);
        System.arraycopy(random_bytes, 0, iv2, 0, random_bytes.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        Cipher cipher2 = Cipher.getInstance("AES/CTR/NoPadding");
        cipher2.init(Cipher.DECRYPT_MODE, secretKey, ivSpec2);

        byte[] ciphertextPrefixAndCounter = new byte[AMSG_PREFIX.length + 2];
        System.arraycopy(padding, 0, ciphertextPrefixAndCounter, 0, ciphertextPrefixAndCounter.length);

        Log.d("MyTest", String.format(
                "Ciphertext prefix and counter: %s",
                Arrays.toString(ciphertextPrefixAndCounter)
        ));

        byte[] plaintextPrefixAndCounter = cipher.doFinal(ciphertextPrefixAndCounter);

        Log.d("MyTest", String.format(
                "Plaintext prefix and counter: %s",
                Arrays.toString(plaintextPrefixAndCounter)
        ));

        byte[] prefix = new byte[AMSG_PREFIX.length];
        System.arraycopy(plaintextPrefixAndCounter, 0, prefix, 0, AMSG_PREFIX.length);

        if (!Arrays.equals(prefix, AMSG_PREFIX)) {
            // No prefix - this is not an anamorphic message
            Log.d("MyTest", "No amsg prefix!");
            return null;
        }

        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.put(plaintextPrefixAndCounter[AMSG_PREFIX.length]);
        buffer.put(plaintextPrefixAndCounter[AMSG_PREFIX.length+1]);
        buffer.position(0);
        short n = buffer.getShort();

        if (n < 0) {
            Log.d("MyTest", "n is negative!");
            return null;
        } else if (n == 0) {
            // not sure why a client would send an empty amsg, but we may as well consider it
            Log.d("MyTest", "n is 0?");
            return "";
        }

        int messageStart = AMSG_PREFIX.length + 2;
        padding = Arrays.copyOf(padding, messageStart + n);

        Log.d("MyTest", String.format(
                "Padding[0..prefix+2+n]: %s",
                Arrays.toString(padding)
        ));

        byte[] plaintext = cipher2.doFinal(padding);

        if (!Arrays.equals(Arrays.copyOf(plaintext, AMSG_PREFIX.length), AMSG_PREFIX)) {
            Log.e("MyTest", "plaintext suddenly does not have prefix!");
        }

        Log.d("MyTest", Arrays.toString(plaintext));

        //remove prefix and length
        plaintext = Arrays.copyOfRange(plaintext, messageStart, messageStart + n);

        // TODO: don't decrypt prefix and counter twice

        String amsg = new String(plaintext);

        Log.d("MyTest", String.format("amsg: %s", amsg));

        return amsg;
    }
}
