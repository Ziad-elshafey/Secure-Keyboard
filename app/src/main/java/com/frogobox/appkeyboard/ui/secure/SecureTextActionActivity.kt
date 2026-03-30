package com.frogobox.appkeyboard.ui.secure

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import com.frogobox.appkeyboard.databinding.ActivitySecureTextActionBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Dialog-style Activity that appears in Android's text selection floating toolbar.
 *
 * Registered with PROCESS_TEXT intent filter so "🔒 Encrypt" and "🔓 Decrypt"
 * appear when user selects text in any app.
 *
 * - **Encrypt mode**: user enters recipient username → selected text is encrypted
 *   and returned to replace the selection.
 * - **Decrypt mode**: selected text is treated as obfuscated text → user enters
 *   sender username → decrypted plaintext is shown.
 */
@AndroidEntryPoint
class SecureTextActionActivity : AppCompatActivity() {

    @Inject
    lateinit var repo: SecureMessagingRepository

    private lateinit var binding: ActivitySecureTextActionBinding

    /** true = encrypt, false = decrypt */
    private var isEncryptMode = true

    /** The text received from the text selection */
    private var selectedText = ""

    /** Whether we can send modified text back to the source app */
    private var isReadOnly = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecureTextActionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Read the selected text from the intent
        selectedText = intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString() ?: ""
        if (selectedText.length > 50_000) { finish(); return }
        isReadOnly = intent.getBooleanExtra(Intent.EXTRA_PROCESS_TEXT_READONLY, false)

        // Determine mode from the component name (activity-alias label)
        val componentName = componentName.className
        isEncryptMode = !componentName.contains("Decrypt", ignoreCase = true)

        // Silent encrypt: if the user already has an active session from the keyboard,
        // skip the dialog entirely and encrypt in-place.
        if (isEncryptMode && selectedText.isNotEmpty()) {
            val prefs = getSharedPreferences("secure_active_session", MODE_PRIVATE)
            val savedSessionId = prefs.getString("session_id", null)
            val savedRecipient = prefs.getString("recipient_name", null)
            if (!savedSessionId.isNullOrEmpty() && !savedRecipient.isNullOrEmpty()) {
                doSilentEncrypt(savedSessionId, savedRecipient)
                return
            }
        }

        // Silent decrypt: if the user already has an active session from the keyboard,
        // skip the dialog entirely and decrypt using the saved peer username.
        if (!isEncryptMode && selectedText.isNotEmpty()) {
            val prefs = getSharedPreferences("secure_active_session", MODE_PRIVATE)
            val savedRecipient = prefs.getString("recipient_name", null)
            if (!savedRecipient.isNullOrEmpty()) {
                doSilentDecrypt(savedRecipient)
                return
            }
        }

        setupUI()

        binding.btnCancel.setOnClickListener { finish() }
        binding.btnAction.setOnClickListener { performAction() }
    }

    /**
     * Encrypt without showing any UI — used when the keyboard already has an active session.
     */
    private fun doSilentEncrypt(sessionId: String, recipientUsername: String) {
        // Show a minimal loading indicator
        binding.tvTitle.text = "🔒 Encrypting..."
        binding.tvLabelText.visibility = View.GONE
        binding.tvSelectedText.visibility = View.GONE
        binding.tvLabelUsername.visibility = View.GONE
        binding.etUsername.visibility = View.GONE
        binding.btnAction.visibility = View.GONE
        binding.btnCancel.visibility = View.GONE
        binding.tvStatus.text = "⏳ Encrypting for $recipientUsername..."
        binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_secondary))

        lifecycleScope.launch(Dispatchers.IO) {
            val result = repo.sendMessage(sessionId, recipientUsername, selectedText)

            withContext(Dispatchers.Main) {
                result.onSuccess { sendResult ->
                    if (!isReadOnly) {
                        val resultIntent = Intent().apply {
                            putExtra(Intent.EXTRA_PROCESS_TEXT, sendResult.obfuscatedText)
                        }
                        setResult(RESULT_OK, resultIntent)
                        finish()
                    } else {
                        binding.tvStatus.text = "✅ Encrypted! Copied to clipboard."
                        binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_success))
                        copyToClipboard(sendResult.obfuscatedText)
                        binding.btnCancel.visibility = View.VISIBLE
                        binding.btnCancel.text = "Done"
                        binding.btnCancel.setOnClickListener { finish() }
                    }
                }.onFailure { e ->
                    // Fall back to showing the dialog
                    binding.tvStatus.text = "❌ ${simplifyError(e)}"
                    binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_danger))
                    binding.btnCancel.visibility = View.VISIBLE
                    binding.btnCancel.setOnClickListener { finish() }
                }
            }
        }
    }

    /**
     * Decrypt without showing any UI — used when the keyboard already has an active session.
     * Uses the saved recipient_name as the sender username for decryption.
     */
    private fun doSilentDecrypt(senderUsername: String) {
        binding.tvTitle.text = "Decrypting..."
        binding.tvLabelText.visibility = View.GONE
        binding.tvSelectedText.visibility = View.GONE
        binding.tvLabelUsername.visibility = View.GONE
        binding.etUsername.visibility = View.GONE
        binding.btnAction.visibility = View.GONE
        binding.btnCancel.visibility = View.GONE
        binding.tvStatus.text = "Decrypting from $senderUsername..."
        binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_secondary))

        lifecycleScope.launch(Dispatchers.IO) {
            val result = repo.decryptMessage(selectedText, senderUsername)

            withContext(Dispatchers.Main) {
                result.onSuccess { plaintext ->
                    if (!isReadOnly) {
                        val resultIntent = Intent().apply {
                            putExtra(Intent.EXTRA_PROCESS_TEXT, plaintext)
                        }
                        setResult(RESULT_OK, resultIntent)
                        finish()
                    } else {
                        binding.tvStatus.text = "Decrypted! Copied to clipboard."
                        binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_success))
                        copyToClipboard(plaintext)
                        binding.btnCancel.visibility = View.VISIBLE
                        binding.btnCancel.text = "Done"
                        binding.btnCancel.setOnClickListener { finish() }
                    }
                }.onFailure { e ->
                    binding.tvStatus.text = simplifyError(e)
                    binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_danger))
                    binding.btnCancel.visibility = View.VISIBLE
                    binding.btnCancel.text = "Close"
                    binding.btnCancel.setOnClickListener { finish() }
                }
            }
        }
    }

    private fun setupUI() {
        if (!repo.isLoggedIn()) {
            binding.tvTitle.text = "🔐 Not Logged In"
            binding.tvSelectedText.text = "Open the app → 🔑 Secure Messaging to login first."
            binding.etUsername.visibility = View.GONE
            binding.btnAction.visibility = View.GONE
            binding.tvLabelUsername.visibility = View.GONE
            binding.tvLabelText.visibility = View.GONE
            return
        }

        binding.tvSelectedText.text = selectedText

        if (isEncryptMode) {
            binding.tvTitle.text = "🔒 Encrypt"
            binding.tvLabelText.text = "Message to encrypt"
            binding.tvLabelUsername.text = "Recipient's username"
            binding.etUsername.hint = "Who should receive this?"
            binding.btnAction.text = "🔒  Encrypt"
        } else {
            binding.tvTitle.text = "🔓 Decrypt"
            binding.tvLabelText.text = "Obfuscated text"
            binding.tvLabelUsername.text = "Sender's username"
            binding.etUsername.hint = "Who sent this?"
            binding.btnAction.text = "🔓  Decrypt"
        }
    }

    private fun performAction() {
        val username = binding.etUsername.text.toString().trim()
        if (username.isEmpty()) {
            binding.tvStatus.text = "Enter a username first"
            binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_danger))
            return
        }

        binding.btnAction.isEnabled = false
        binding.tvStatus.text = if (isEncryptMode) "⏳ Encrypting..." else "⏳ Decrypting..."
        binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_secondary))

        if (isEncryptMode) {
            doEncrypt(username)
        } else {
            doDecrypt(username)
        }
    }

    private fun doEncrypt(recipientUsername: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            // Find session with this recipient
            val sessionResult = findSessionForPeer(recipientUsername)

            if (sessionResult == null) {
                withContext(Dispatchers.Main) {
                    binding.btnAction.isEnabled = true
                    binding.tvStatus.text = "❌ No active session with '$recipientUsername' — start a conversation first"
                    binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_danger))
                }
                return@launch
            }

            val (sessionId, _) = sessionResult
            val result = repo.sendMessage(sessionId, recipientUsername, selectedText)

            withContext(Dispatchers.Main) {
                binding.btnAction.isEnabled = true
                result.onSuccess { sendResult ->
                    if (!isReadOnly) {
                        // Return encrypted text to replace selection in source app
                        val resultIntent = Intent().apply {
                            putExtra(Intent.EXTRA_PROCESS_TEXT, sendResult.obfuscatedText)
                        }
                        setResult(RESULT_OK, resultIntent)
                        finish()
                    } else {
                        // ReadOnly — can't replace, just show the obfuscated text
                        binding.tvStatus.text = "✅ Encrypted! (source is read-only, text copied to clipboard)"
                        binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_success))
                        copyToClipboard(sendResult.obfuscatedText)
                    }
                }.onFailure { e ->
                    binding.tvStatus.text = "❌ ${simplifyError(e)}"
                    binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_danger))
                }
            }
        }
    }

    private fun doDecrypt(senderUsername: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val result = repo.decryptMessage(selectedText, senderUsername)

            withContext(Dispatchers.Main) {
                binding.btnAction.isEnabled = true
                result.onSuccess { plaintext ->
                    binding.tvStatus.text = "✅ Decrypted successfully"
                    binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_success))
                    // Show decrypted text in the preview area
                    binding.tvLabelText.text = "Decrypted message"
                    binding.tvSelectedText.text = plaintext
                    binding.tvSelectedText.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_primary))
                }.onFailure { e ->
                    binding.tvStatus.text = "❌ ${simplifyError(e)}"
                    binding.tvStatus.setTextColor(getColor(com.frogobox.appkeyboard.R.color.secure_text_danger))
                }
            }
        }
    }

    /**
     * Find the session ID for a given peer username.
     * Returns (sessionId, peerUsername) or null if no active session exists.
     */
    private suspend fun findSessionForPeer(peerUsername: String): Pair<String, String>? {
        val sessions = repo.listSessions().getOrNull() ?: return null
        val myUserId = repo.getUserId()

        return sessions.filter { it.isActive }.firstOrNull { session ->
            val peer = if (session.initiatorId == myUserId)
                session.responderUsername
            else
                session.initiatorUsername
            peer.equals(peerUsername, ignoreCase = true)
        }?.let { Pair(it.sessionId, peerUsername) }
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Text", text))
    }

    private fun simplifyError(e: Throwable): String {
        val msg = e.message ?: "Unknown error"
        return when {
            msg.contains("ConnectException") || msg.contains("Failed to connect") ->
                "Cannot connect to server"
            msg.contains("No shared secret") ->
                "No encryption keys — start a conversation first"
            msg.contains("session") && msg.contains("not found", ignoreCase = true) ->
                "No session with this user"
            else -> msg.take(120)
        }
    }
}
