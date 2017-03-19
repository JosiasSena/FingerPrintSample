package com.example.josiassena.fingerprint;

import android.annotation.TargetApi;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    // Variable used for storing the key in the Android Keystore container
    private static final String KEY_STORE_ALIAS = "key_fingerprint";
    private static final String KEY_STORE = "AndroidKeyStore";

    private KeyStore keyStore;
    private Cipher cipher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Get an instance of the fingerprint manager through the getSystemService method
        final FingerprintManager fingerprintManager =
                (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        // Our fingerprint checker
        final FingerPrintChecker checker = new FingerPrintChecker(this, fingerprintManager);

        if (checker.isAbleToUseFingerPrint()) {
            generateAuthenticationKey();

            if (isCipherInitialized()) {
                // A wrapper for the crypto objects supported by the FingerprintManager
                final FingerprintManager.CryptoObject cryptoObject =
                        new FingerprintManager.CryptoObject(cipher);

                // Our fingerprint callback helper
                final FingerprintHelper fingerprintHelper = new FingerprintHelper(this);
                fingerprintHelper.authenticate(fingerprintManager, cryptoObject);
            }
        }
    }

    /**
     * Generates the authentication key required to use with the {@link FingerprintManager} to
     * encrypt/decrypt fingerprints.
     */
    @TargetApi (Build.VERSION_CODES.M)
    private void generateAuthenticationKey() {

        getKeyStoreInstance();

        final KeyGenerator keyGenerator = getKeyGenerator();

        try {
            keyStore.load(null);

            final KeyGenParameterSpec parameterSpec = getKeyGenParameterSpec();

            // Initialize th key generator
            keyGenerator.init(parameterSpec);

            // Generate the key. This also returns the generated key for immediate use if needed.
            // For this example we will grab it later on.
            keyGenerator.generateKey();

        } catch (NoSuchAlgorithmException |
                InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate the {@link KeyGenParameterSpec} required for us to encrypt/decrypt.
     */
    @NonNull
    private KeyGenParameterSpec getKeyGenParameterSpec() {
        // Specify what we are trying to do with the generated key
        final int purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;

        // Specifications for the key generator. How to generate the key
        return new KeyGenParameterSpec.Builder(KEY_STORE_ALIAS, purposes)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();
    }

    /**
     * Get an instance of the Java {@link KeyStore}
     */
    private void getKeyStoreInstance() {
        try {
            keyStore = KeyStore.getInstance(KEY_STORE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the key generator required to generate the keys uses for encryption/decryption
     */
    private KeyGenerator getKeyGenerator() {
        final KeyGenerator keyGenerator;

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get KeyGenerator instance", e);
        }

        return keyGenerator;
    }

    /**
     * Initializes the Cipher object required to perform the fingerprint authentication.
     *
     * @return True if Cipher init was successful. False otherwise.
     */
    @TargetApi (Build.VERSION_CODES.M)
    private boolean isCipherInitialized() {
        try {
            // Get a cipher instance with the following transformation --> AES/CBC/PKCS7Padding
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" +
                    KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get cipher instance", e);
        }

        try {
            keyStore.load(null);

            // The key - This key was generated in the {@link #generateAuthenticationKey()} method
            final SecretKey key = (SecretKey) keyStore.getKey(KEY_STORE_ALIAS, null);

            // Finally, initialize the cipher object
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException |
                IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }
}
