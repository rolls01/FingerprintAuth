package com.michalrola.fingerprintauth

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.app.ActivityCompat
import android.support.v7.app.AppCompatActivity
import android.widget.TextView
import android.widget.Toast
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {

    private val KEY_NAME = "example_key"
    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var cipher: Cipher
    private lateinit var cryptoObject: FingerprintManager.CryptoObject

    lateinit var encryptedTextView: TextView
    lateinit var decryptedTextView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        encryptedTextView = findViewById(R.id.encryptedTextView) as TextView
        decryptedTextView = findViewById(R.id.decryptedTextView) as TextView

        keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager

       checkFingerprint()

        generateKey()

        if (cipherInit()) {
            cryptoObject = FingerprintManager.CryptoObject(cipher)
            val fingerprintHandler = FingerprintHandler(this)
            fingerprintHandler.startAuth(fingerprintManager, cryptoObject)
        }

        val PIN = "1234"

        val keySalt = "trochę soli do rosołu".toByteArray()
        val keyGenerated = KeyGenerator.getInstance("AES")
        val strongRandomNumber = SecureRandom.getInstance("SHA1PRNG")
        strongRandomNumber.setSeed(keySalt)
        keyGenerated.init(256, strongRandomNumber)
        val secretKey = keyGenerated.generateKey()
//        val key = secretKey.encoded

// encrypt
        val encryptedData = encrypt(secretKey.encoded, PIN.toByteArray())
        encryptedTextView.text = encryptedData.toString()
// decrypt
        val decryptedData = decrypt(secretKey.encoded, encryptedData)
        decryptedTextView.text = decryptedData.toString(Charsets.UTF_8)

//        val plaintext = "secret".toByteArray()
//        val keygen = KeyGenerator.getInstance("AES")
//        keygen.init(256)
//        val key = keygen.generateKey()
//        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
//        cipher.init(Cipher.ENCRYPT_MODE, key)
//        val ciphertext = cipher.doFinal(plaintext)
//        val iv = cipher.iv
//
//        encryptedTextView.text = ciphertext.toString()
//        decryptedTextView.text = plaintext.toString(Charsets.UTF_8)


    }

    private fun checkFingerprint() {
        if (!keyguardManager.isKeyguardSecure) {
            Toast.makeText(this, "Lock screen security not enabled in Settings", Toast.LENGTH_SHORT).show()
            return
        }

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
            != PackageManager.PERMISSION_GRANTED
        ) {
            Toast.makeText(
                this,
                "Fingerprint authentication permission not enabled",
                Toast.LENGTH_LONG
            ).show()
            return
        }
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            Toast.makeText(
                this,
                "Register at least one fingerprint in Settings",
                Toast.LENGTH_LONG
            ).show()
            return
        }
    }

    protected fun generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: Exception) {
            e.printStackTrace()
        }

        try {
            keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(
                "Failed to get KeyGenerator instance", e
            )
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get KeyGenerator instance", e)
        }

        try {
            keyStore.load(null)
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT or
                            KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                        KeyProperties.ENCRYPTION_PADDING_PKCS7
                    )
                    .build()
            )
            keyGenerator.generateKey()
        } catch (noSuchAlgorithmException: NoSuchAlgorithmException) {
            throw RuntimeException(noSuchAlgorithmException)
        } catch (invalidAlgorithmParameterException: InvalidAlgorithmParameterException) {
            throw RuntimeException(invalidAlgorithmParameterException)
        } catch (certificateException: CertificateException) {
            throw RuntimeException(certificateException)
        } catch (iOException: IOException) {
            throw RuntimeException(iOException)
        }

    }

    fun cipherInit(): Boolean {
        try {
            cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get Cipher", e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException("Failed to get Cipher", e)
        }

        try {
            keyStore.load(null)
            val key: SecretKey = keyStore.getKey(KEY_NAME, null) as SecretKey

            cipher.init(Cipher.ENCRYPT_MODE, key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false;
        } catch (e: Exception) {
            throw RuntimeException("Failed to init Cipher", e);
        }

    }

    @Throws(Exception::class)
    private fun encrypt(raw: ByteArray, clear: ByteArray): ByteArray {
        val skeySpec = SecretKeySpec(raw, "AES")
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec)
        return cipher.doFinal(clear)
    }

    @Throws(Exception::class)
    private fun decrypt(raw: ByteArray, encrypted: ByteArray): ByteArray {
        val skeySpec = SecretKeySpec(raw, "AES")
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.DECRYPT_MODE, skeySpec)
        return cipher.doFinal(encrypted)
    }

}

