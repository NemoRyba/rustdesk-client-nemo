package com.carriez.flutter_hbb

import android.app.Application
import android.util.Log
import ffi.FFI

class MainApplication : Application() {
    companion object {
        private const val TAG = "MainApplication"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "App start")
        FFI.onAppStart(applicationContext)
        // TBFDesk P-2: register the device-key Keystore helper in every process (incl. a
        // BootReceiver-started service) before the management poll first reads the key.
        FFI.nemoSetKeystoreHelper(KeystoreHelper())
    }
}
