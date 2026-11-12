// ffi.kt

package ffi

import android.content.Context
import java.nio.ByteBuffer

import com.carriez.flutter_hbb.RdClipboardManager
import com.carriez.flutter_hbb.KeystoreHelper

object FFI {
    init {
        System.loadLibrary("rustdesk")
    }

    external fun init(ctx: Context)
    external fun onAppStart(ctx: Context)
    // TBFDesk P-2: hand Rust the KeystoreHelper so the device key is wrapped at rest.
    external fun nemoSetKeystoreHelper(helper: KeystoreHelper)
    external fun setClipboardManager(clipboardManager: RdClipboardManager)
    external fun startServer(app_dir: String, custom_client_config: String)
    external fun startService()
    external fun onVideoFrameUpdate(buf: ByteBuffer)
    external fun onAudioFrameUpdate(buf: ByteBuffer)
    external fun translateLocale(localeName: String, input: String): String
    external fun refreshScreen()
    external fun setFrameRawEnable(name: String, value: Boolean)
    external fun setCodecInfo(info: String)
    external fun getLocalOption(key: String): String
    external fun getBuildinOption(key: String): String
    external fun onClipboardUpdate(clips: ByteBuffer)
    external fun isServiceClipboardEnabled(): Boolean
}
