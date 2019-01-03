package com.michalrola.fingerprintauth

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.support.v4.app.ActivityCompat
import android.util.Log
import android.widget.Toast
import javax.crypto.Cipher

class FingerprintHandler(context: Context): FingerprintManager.AuthenticationCallback() {

    lateinit var cancellationSignal: CancellationSignal
    var context: Context

    init{
        this.context = context
    }

    fun startAuth(fingerprintManager: FingerprintManager, cryptoObject: FingerprintManager.CryptoObject){
        cancellationSignal = CancellationSignal()

        if(ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED){
            return
        }
        fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null)

        Toast.makeText(context,
            "authentificate in startAuth",
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        Toast.makeText(context,
            "Authentication error\n" + errString,
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
        Toast.makeText(context,
            "Authentication succeeded. ",
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        Toast.makeText(context,
            "Authentication help\n" + helpString,
            Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationFailed() {
        Toast.makeText(context,
            "Authentication failed.",
            Toast.LENGTH_LONG).show()
    }
}