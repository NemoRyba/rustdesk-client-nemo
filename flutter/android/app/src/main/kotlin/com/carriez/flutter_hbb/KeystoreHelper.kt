package com.carriez.flutter_hbb

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * TBFDesk P-2 (device key at rest).
 *
 * Wraps and unwraps the TBFDesk device key with a non-exportable AES-256-GCM key held in the
 * Android Keystore, so the Ed25519 device-key seed is NOT a cat-able secret sitting in
 * TBFDesk2.toml. The key is generated once per install under a fixed alias and never leaves
 * the Keystore; only ciphertext (iv ‖ ct+tag, base64) is persisted.
 *
 * No user-authentication requirement is set on purpose: a provisioned device operates
 * unattended, so requiring a biometric/PIN to use the key would break headless remote access.
 *
 * Honest limit (do not read this as "P-2 closed"): the Android Keystore authorises by the
 * CALLING UID, and the in-app console shell runs as that same app uid, so it too could ask
 * keystore2 to unwrap. This removes the plaintext key at rest and forces an attacker to run
 * Keystore-calling code inside the app's context rather than reading a file -- a bar-raise,
 * not a hard boundary. A hard boundary needs the shell to run under a different uid.
 *
 * Called from Rust via JNI (libs/scrap/src/android/ffi.rs: nemo_device_key_wrap/unwrap).
 * Methods throw on failure; the Rust side clears the pending exception and treats the key as
 * absent, never falling back to cleartext.
 */
class KeystoreHelper {
    companion object {
        private const val TAG = "KeystoreHelper"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "tbfdesk_device_key_v1"
        private const val GCM_TAG_BITS = 128
        private const val IV_LEN = 12
    }

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        Log.d(TAG, "generating device-key wrapping key in the Android Keystore")
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    /** plaintext -> base64(iv ‖ ciphertext+tag). A fresh random IV per call (GCM default). */
    fun wrap(plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = cipher.iv
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val out = ByteArray(iv.size + ct.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ct, 0, out, iv.size, ct.size)
        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    /** base64(iv ‖ ciphertext+tag) -> plaintext. Throws if the blob or tag does not verify. */
    fun unwrap(blob: String): String {
        val raw = Base64.decode(blob, Base64.NO_WRAP)
        require(raw.size > IV_LEN) { "device-key blob too short" }
        val iv = raw.copyOfRange(0, IV_LEN)
        val ct = raw.copyOfRange(IV_LEN, raw.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }
}
