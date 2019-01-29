package com.michalrola.fingerprintauth

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Bundle
import android.support.v4.app.ActivityCompat
import android.support.v7.app.AppCompatActivity
import android.widget.EditText
import android.widget.Toast
import com.michalrola.fingerprintauth.authentication.EncryptionObject
import kotlinx.android.synthetic.main.activity_main.*


class MainActivity : AppCompatActivity() {

    companion object {
        val TAG = MainActivity::class.java.simpleName
        private const val SECURE_KEY = "data.source.prefs.SECURE_KEY"
    }

    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var cryptoObjectEncrypt: FingerprintManager.CryptoObject
    private lateinit var cryptoObjectDecrypt: FingerprintManager.CryptoObject
    private var encryptedMessage: String = "" //should have: message + separator + IV from first cipher
    private val separator = "-"
    private lateinit var pref: SharedPreferences
    private lateinit var editor: SharedPreferences.Editor

    //    private lateinit var encryptedTextView: TextView
//    private lateinit var decryptedTextView: TextView
//    private lateinit var encryptButton: Button
//    private lateinit var decryptButton: Button
//    private lateinit var listenerButton: Button
//    private lateinit var listenerButtonEnc: Button
    private lateinit var pinEditText: EditText

    private val encryptionObject = EncryptionObject.newInstance()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

//        encryptedTextView = findViewById(R.id.encryptedTextView) as TextView
//        decryptedTextView = findViewById(R.id.decryptedTextView) as TextView
//        encryptButton = findViewById(R.id.encryptButton) as Button
//        decryptButton = findViewById(R.id.decryptButton) as Button
//        listenerButton = findViewById(R.id.listenerButton) as Button
//        listenerButtonEnc = findViewById(R.id.listenerButtonEnc) as Button
        pinEditText = findViewById(R.id.pinEditText) as EditText

        keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager


        pref = this.getSharedPreferences(
            "com.michalrola.secure.pref",
            Context.MODE_PRIVATE
        )

        editor = pref.edit()
        checkFingerprint()

        val encryptedTextFromSharedPref =
            if (pref.getString(SECURE_KEY, null) != null) pref.getString(SECURE_KEY, null) else ""

        encryptedTextView.text = encryptedTextFromSharedPref
        encryptedMessage = encryptedTextFromSharedPref


        listenerButtonEnc.setOnClickListener {
            createFingerprintHandlerEnc()
        }

        encryptButton.setOnClickListener {
            encryptMessage()
        }
        listenerButton.setOnClickListener {
            createFingerprintHandlerDec()
        }

        decryptButton.setOnClickListener {
            decryptMessage()
        }
    }

    private fun decryptMessage() {
        val mess = pref.getString(SECURE_KEY, null).split(separator)[0]
        val decryptedData = encryptionObject.decrypt(
            encryptionObject.cipherDec,
            mess
        )
        decryptedTextView.text = decryptedData
    }

    private fun encryptMessage() {
        try {
            encryptedMessage = encryptionObject.encrypt(
                encryptionObject.cipherEnc,
                pinEditText.text.toString().toByteArray(Charsets.UTF_8),
                separator
            )
            editor.putString(SECURE_KEY, encryptedMessage)
            editor.apply()

            encryptedTextView.text = encryptedMessage
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun createFingerprintHandlerEnc() {
        try {
            cryptoObjectEncrypt = FingerprintManager.CryptoObject(encryptionObject.cipherForEncryption())
            val fingerprintHandler = FingerprintHandler(this)
            fingerprintHandler.startAuth(fingerprintManager, cryptoObjectEncrypt)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun createFingerprintHandlerDec() {
        try {
            cryptoObjectDecrypt = FingerprintManager.CryptoObject(
                encryptionObject.cipherForDecryption(
                    pref.getString(SECURE_KEY, null).split(separator)[1].replace("\n", "")
                )
            )
            val fingerprintHandler = FingerprintHandler(this)
            fingerprintHandler.startAuth(fingerprintManager, cryptoObjectDecrypt)
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
        }
    }

    private fun checkFingerprint() {
        if (!keyguardManager.isKeyguardSecure) {
            Toast.makeText(this, getString(R.string.fingerpint_not_entabled_message), Toast.LENGTH_SHORT).show()
            return
        }

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
            != PackageManager.PERMISSION_GRANTED
        ) {
            Toast.makeText(
                this,
                getString(R.string.fingerpint_permissions_not_entabled_message),
                Toast.LENGTH_LONG
            ).show()
            return
        }
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            Toast.makeText(
                this,
                getString(R.string.fingerpint_not_registered_message),
                Toast.LENGTH_LONG
            ).show()
            return
        }
    }


}

