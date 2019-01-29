package com.michalrola.fingerprintauth

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.support.v4.app.ActivityCompat
import android.widget.Toast

class FingerprintHandler(private val context: Context) : FingerprintManager.AuthenticationCallback() {

    lateinit var cancellationSignal: CancellationSignal

    fun startAuth(fingerprintManager: FingerprintManager, cryptoObject: FingerprintManager.CryptoObject) {
        cancellationSignal = CancellationSignal()

        if (ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.USE_FINGERPRINT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null)
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        informationMessage(context.getString(R.string.auth_error_message))
    }

    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
        informationMessage(context.getString(R.string.aith_success_message))
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        informationMessage(context.getString(R.string.auth_help_message))
    }

    override fun onAuthenticationFailed() {
        informationMessage(context.getString(R.string.auth_failed_message))
    }

    private fun informationMessage(message: String) {
        Toast.makeText(
            context,
            message,
            Toast.LENGTH_LONG
        ).show()
    }

}