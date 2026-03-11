package com.frogobox.appkeyboard.core

import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.text.TextUtils
import com.frogobox.appkeyboard.services.DecryptAccessibilityService

/**
 * Shared singleton for coordinating decrypt-on-tap between
 * KeyboardIME and DecryptAccessibilityService.
 * Both run in the same app process so a simple object works.
 */
object DecryptCaptureState {

    @Volatile
    var isCapturing: Boolean = false
        private set

    var recipientName: String? = null
        private set

    var onTextCaptured: ((String) -> Unit)? = null
        private set

    /** Reference set by the AccessibilityService in onServiceConnected */
    var serviceInstance: DecryptAccessibilityService? = null

    fun startCapture(recipientName: String, callback: (String) -> Unit) {
        this.recipientName = recipientName
        this.onTextCaptured = callback
        this.isCapturing = true
        serviceInstance?.showTapCaptureOverlay()
    }

    fun stopCapture() {
        isCapturing = false
        onTextCaptured = null
        recipientName = null
        serviceInstance?.removeAllOverlays()
    }

    fun deliverText(text: String) {
        val cb = onTextCaptured
        isCapturing = false
        onTextCaptured = null
        recipientName = null
        serviceInstance?.removeAllOverlays()
        cb?.invoke(text)
    }

    fun isServiceEnabled(context: Context): Boolean {
        val expected = ComponentName(context, DecryptAccessibilityService::class.java)
        val enabledServices = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        val colonSplitter = TextUtils.SimpleStringSplitter(':')
        colonSplitter.setString(enabledServices)
        while (colonSplitter.hasNext()) {
            val componentName = colonSplitter.next()
            if (ComponentName.unflattenFromString(componentName) == expected) {
                return true
            }
        }
        return false
    }
}
