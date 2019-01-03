package com.michalrola.fingerprintauth

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Bundle
import android.support.v4.app.ActivityCompat
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import com.michalrola.fingerprintauth.authentication.EncryptionObject


class MainActivity : AppCompatActivity() {

    companion object {
        val TAG = MainActivity::class.java.simpleName
    }

    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var cryptoObjectEncrypt: FingerprintManager.CryptoObject
    private lateinit var cryptoObjectDecrypt: FingerprintManager.CryptoObject
    private var encryptedMessage: String = "" //should have: message + separator + IV from first cipher
    private val separator = "-"

    private lateinit var encryptedTextView: TextView
    private lateinit var decryptedTextView: TextView
    private lateinit var encryptButton: Button
    private lateinit var decryptButton: Button
    private lateinit var listenerButton: Button
    private lateinit var listenerButtonEnc: Button
    private lateinit var pinEditText: EditText

    private val encryptionObject = EncryptionObject.newInstance()

    private val SECURE_KEY = "data.source.prefs.SECURE_KEY"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        encryptedTextView = findViewById(R.id.encryptedTextView) as TextView
        decryptedTextView = findViewById(R.id.decryptedTextView) as TextView
        encryptButton = findViewById(R.id.encryptButton) as Button
        decryptButton = findViewById(R.id.decryptButton) as Button
        listenerButton = findViewById(R.id.listenerButton) as Button
        listenerButtonEnc = findViewById(R.id.listenerButtonEnc) as Button
        pinEditText = findViewById(R.id.PINexitText) as EditText

        keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager


        var pref = this.getSharedPreferences(
            "com.michalrola.secure.pref",
            Context.MODE_PRIVATE
        )

        var editor = pref.edit()

//        val mBottomSheetDialog = BottomSheetDialog(this)
//        val sheetView = this.layoutInflater.inflate(R.layout.fingerprint_dialog, null)
//        mBottomSheetDialog.setContentView(sheetView)
//        mBottomSheetDialog.show()

        checkFingerprint()

        val encryptedTextFromSharedPref =
            if (pref.getString(SECURE_KEY, null) != null) pref.getString(SECURE_KEY, null) else ""

        encryptedTextView.text = encryptedTextFromSharedPref
        encryptedMessage = encryptedTextFromSharedPref


        listenerButtonEnc.setOnClickListener {
            try {
//                mBottomSheetDialog.show()
                cryptoObjectEncrypt = FingerprintManager.CryptoObject(encryptionObject.cipherForEncryption())
                val fingerprintHandler = FingerprintHandler(this)
                fingerprintHandler.startAuth(fingerprintManager, cryptoObjectEncrypt)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        encryptButton.setOnClickListener {
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
        listenerButton.setOnClickListener {

            cryptoObjectDecrypt = FingerprintManager.CryptoObject(
                encryptionObject.cipherForDecryption(
                    pref.getString(SECURE_KEY, null).split(separator)[1].replace("\n", "")
                )
            )
            val fingerprintHandler = FingerprintHandler(this)
            fingerprintHandler.startAuth(fingerprintManager, cryptoObjectDecrypt)
        }

        decryptButton.setOnClickListener {
            val mess = pref.getString(SECURE_KEY, null).split(separator)[0]
            val decryptedData = encryptionObject.decrypt(
                encryptionObject.cipherDec,
                mess
            )
            decryptedTextView.text = decryptedData
        }
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


}

