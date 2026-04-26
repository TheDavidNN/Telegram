package org.telegram.messenger;

public class AnamorphicMessage {
    public byte[] iv;
    public byte[] formattedCiphertext;

    public AnamorphicMessage(byte[] iv, byte[] formattedCiphertext) {
        this.iv = iv;
        this.formattedCiphertext = formattedCiphertext;
    }
}
