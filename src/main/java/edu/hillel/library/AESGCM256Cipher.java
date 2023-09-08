/*
 * The MIT License
 *
 * Copyright 2023 Tymur Kosiak ( https://github.com/iBubbleGun ).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package edu.hillel.library;

import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * The type Aesgcm 256 cipher.
 *
 * @author Tymur Kosiak <a href="https://github.com/iBubbleGun">iBubbleGun</a>
 */
public class AESGCM256Cipher {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private final String ALGORITHM;

    /**
     * Instantiates a new Aesgcm 256 cipher.
     */
    public AESGCM256Cipher() {
        this.ALGORITHM = "AES/GCM/NoPadding";
    }

    /**
     * Encrypt string.
     *
     * @param plaintext the plaintext
     * @param secretKey the secret key
     * @return the string
     * @throws Exception the exception
     */
    public String encrypt(@NotNull String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(this.ALGORITHM);
        byte[] iv = generateIV();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] combinedIVAndCipherText = new byte[GCM_IV_LENGTH + encryptedBytes.length];
        System.arraycopy(iv, 0, combinedIVAndCipherText, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedBytes, 0, combinedIVAndCipherText, GCM_IV_LENGTH, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combinedIVAndCipherText);
    }

    /**
     * Decrypt string.
     *
     * @param encryptedText the encrypted text
     * @param secretKey     the secret key
     * @return the string
     * @throws Exception the exception
     */
    public String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedBytes, 0, iv, 0, GCM_IV_LENGTH);
        Cipher cipher = Cipher.getInstance(this.ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes, GCM_IV_LENGTH, encryptedBytes.length - GCM_IV_LENGTH);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Generate aes key secret key.
     *
     * @param KEY_SIZE the key size
     * @return the secret key
     * @throws Exception the exception
     */
    public SecretKey generateAESKey(final int KEY_SIZE) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private byte @NotNull [] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
}
