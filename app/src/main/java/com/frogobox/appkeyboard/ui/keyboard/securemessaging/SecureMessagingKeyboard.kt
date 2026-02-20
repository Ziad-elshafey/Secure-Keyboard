package com.frogobox.appkeyboard.ui.keyboard.securemessaging

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.inputmethod.ExtractedTextRequest
import android.widget.LinearLayout
import com.frogobox.appkeyboard.databinding.KeyboardSecureMessagingBinding
import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import com.frogobox.appkeyboard.di.SecureKeyboardEntryPoint
import com.frogobox.libkeyboard.common.core.BaseKeyboard
import dagger.hilt.android.EntryPointAccessors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Secure Messaging Keyboard — Full E2EE + Steganographic Obfuscation (v3.0)
 *
 * Auth (login / register) is handled in the main app (SecureAuthActivity).
 * This panel handles compose / decrypt when already logged in.
 *
 * The panel sits ABOVE the QWERTY keys (form-pattern layout).
 * Text input uses embedded EditText fields so the user can type
 * without leaving the secure messaging panel.
 *
 * States (ViewFlipper indices):
 *   0 = NOT_LOGGED_IN  (instruction to open the app)
 *   1 = COMPOSE        (search user → create session → send encrypted)
 *   2 = DECRYPT        (paste encrypted text → deobfuscate → decrypt)
 *   3 = DECRYPT RESULT (revealed + decrypted plaintext)
 */
class SecureMessagingKeyboard(
    context: Context,
    attrs: AttributeSet?,
) : BaseKeyboard<KeyboardSecureMessagingBinding>(context, attrs) {

    companion object {
        private const val STATE_NOT_LOGGED_IN = 0
        private const val STATE_COMPOSE = 1
        private const val STATE_INBOX = 2
        private const val STATE_DECRYPT = 3
    }

    private var _repo: SecureMessagingRepository? = null
    private val repo: SecureMessagingRepository
        get() {
            if (_repo == null) {
                _repo = EntryPointAccessors.fromApplication(
                    context.applicationContext,
                    SecureKeyboardEntryPoint::class.java
                ).secureMessagingRepository()
            }
            return _repo!!
        }

    // Session state for compose flow
    private var selectedRecipientId: String? = null
    private var selectedRecipientName: String? = null
    private var activeSessionId: String? = null

    // Guard against double-init
    private var uiInitialized = false

    override fun setupViewBinding(
        inflater: LayoutInflater,
        parent: LinearLayout
    ): KeyboardSecureMessagingBinding {
        return KeyboardSecureMessagingBinding.inflate(LayoutInflater.from(context), this, true)
    }

    override fun initUI() {
        super.initUI()
        // Defer heavy init — repo / Hilt may not be ready during XML inflation.
        // Actual setup happens in onAttachedToWindow().
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (uiInitialized) return
        uiInitialized = true

        setupComposeState()
        setupDecryptInputState()
        setupDecryptResultState()
        refreshAuthState()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        // Refresh auth state when panel becomes visible (e.g. after user logs in elsewhere)
        if (changedView == this && visibility == View.VISIBLE && uiInitialized) {
            refreshAuthState()
        }
    }

    /** Re-check login state and update UI. Call when panel becomes visible after auth may have changed. */
    private fun refreshAuthState() {
        try {
            if (repo.isLoggedIn()) {
                showState(STATE_COMPOSE)
            } else {
                showState(STATE_NOT_LOGGED_IN)
            }
        } catch (e: Exception) {
            showState(STATE_NOT_LOGGED_IN)
        }
    }

    // ═════════════════════════════════════════════════════════
    //  State Management
    // ═════════════════════════════════════════════════════════

    private fun showState(state: Int) {
        val loggedIn = try { repo.isLoggedIn() } catch (_: Exception) { false }

        // If any authenticated state is requested but we're not logged in, redirect
        if (!loggedIn && state != STATE_NOT_LOGGED_IN) {
            binding.viewFlipper.displayedChild = STATE_NOT_LOGGED_IN
            binding.btnInbox.visibility = View.GONE
            binding.btnCompose.visibility = View.GONE
            binding.btnLogout.visibility = View.GONE
            binding.tvToolbarTitle.text = "Secure Messaging"
            return
        }

        binding.viewFlipper.displayedChild = state
        binding.btnInbox.visibility = if (loggedIn) View.VISIBLE else View.GONE
        binding.btnCompose.visibility = if (loggedIn) View.VISIBLE else View.GONE
        binding.btnLogout.visibility = if (loggedIn) View.VISIBLE else View.GONE

        val username = repo.getUsername() ?: "Secure Messaging"
        binding.tvToolbarTitle.text = when (state) {
            STATE_NOT_LOGGED_IN -> "Secure Messaging"
            STATE_COMPOSE -> "✏️ $username"
            STATE_INBOX -> "� Decrypt"
            STATE_DECRYPT -> "🔓 Decrypt"
            else -> "Secure Messaging"
        }

        // Toolbar nav buttons
        binding.btnInbox.setOnClickListener {
            showState(STATE_INBOX)
        }
        binding.btnCompose.setOnClickListener { showState(STATE_COMPOSE) }
        binding.btnLogout.setOnClickListener {
            repo.logout()
            resetComposeState()
            showState(STATE_NOT_LOGGED_IN)
        }
    }

    // ═════════════════════════════════════════════════════════
    //  State 1: COMPOSE
    // ═════════════════════════════════════════════════════════

    private fun setupComposeState() {
        binding.btnSearch.setOnClickListener { searchUser() }
        binding.btnStartConversation.setOnClickListener { startConversation() }
        binding.btnSend.setOnClickListener { sendMessage() }
    }

    private fun searchUser() {
        val query = binding.etUsername.text.toString().trim()
        if (query.isEmpty()) {
            binding.tvSearchResult.visibility = View.VISIBLE
            binding.tvSearchResult.text = "Type a username above first"
            return
        }

        binding.tvSearchResult.visibility = View.VISIBLE
        binding.tvSearchResult.text = "🔍 Searching for '$query'..."
        binding.btnStartConversation.visibility = View.GONE
        binding.composeArea.visibility = View.GONE

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.searchUsers(query)
            withContext(Dispatchers.Main) {
                result.onSuccess { users ->
                    val others = users.filter { it.userId != repo.getUserId() }
                    if (others.isEmpty()) {
                        binding.tvSearchResult.text = "No users found matching '$query'"
                    } else {
                        val user = others.first()
                        selectedRecipientId = user.userId
                        selectedRecipientName = user.username
                        binding.tvSearchResult.text = "Found: ${user.username}"
                        binding.btnStartConversation.visibility = View.VISIBLE
                        binding.btnStartConversation.text = "💬 Start conversation with ${user.username}"
                    }
                }.onFailure { e ->
                    binding.tvSearchResult.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    private fun startConversation() {
        val recipientId = selectedRecipientId ?: return
        val recipientName = selectedRecipientName ?: return
        binding.btnStartConversation.isEnabled = false
        binding.tvSearchResult.text = "⏳ Creating session..."

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.createSession(recipientName, recipientId)
            withContext(Dispatchers.Main) {
                binding.btnStartConversation.isEnabled = true
                result.onSuccess { sessionInfo ->
                    activeSessionId = sessionInfo.sessionId
                    binding.composeArea.visibility = View.VISIBLE
                    binding.tvComposeLabel.text = "Messaging: $selectedRecipientName"
                    binding.tvSendStatus.text = ""
                    binding.scrollObfuscated.visibility = View.GONE
                    binding.tvSearchResult.text = "✅ Session ready"
                    binding.btnStartConversation.visibility = View.GONE
                }.onFailure { e ->
                    binding.tvSearchResult.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    /**
     * Read plaintext from the HOST APP's text field, encrypt + obfuscate,
     * then REPLACE the host field content with the obfuscated text.
     */
    private fun sendMessage() {
        val sessionId = activeSessionId ?: return
        val ic = currentInputConnection

        if (ic == null) {
            binding.tvSendStatus.text = "❌ No active text field — tap on a text field first"
            return
        }

        // Read the entire content of the host app's text field
        val extracted = ic.getExtractedText(ExtractedTextRequest(), 0)
        val plaintext = extracted?.text?.toString()?.trim() ?: ""

        if (plaintext.isEmpty()) {
            binding.tvSendStatus.text = "Type your message in the text field above first"
            return
        }

        binding.btnSend.isEnabled = false
        binding.tvSendStatus.text = "⏳ Encrypting & obfuscating..."

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.sendMessage(sessionId, selectedRecipientName ?: "", plaintext)
            withContext(Dispatchers.Main) {
                binding.btnSend.isEnabled = true
                result.onSuccess { sendResult ->
                    // Clear the original plaintext and replace with obfuscated text
                    ic.apply {
                        performContextMenuAction(android.R.id.selectAll)
                        commitText(sendResult.obfuscatedText, 1)
                    }

                    binding.tvSendStatus.text = "✅ Encrypted message placed in text field. Send it!"
                    binding.scrollObfuscated.visibility = View.VISIBLE
                    binding.tvObfuscatedPreview.text =
                        "Decoy: \"${sendResult.obfuscatedText.take(80)}...\""
                }.onFailure { e ->
                    binding.tvSendStatus.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    private fun resetComposeState() {
        selectedRecipientId = null
        selectedRecipientName = null
        activeSessionId = null
    }

    // ═════════════════════════════════════════════════════════
    //  State 2: DECRYPT (was INBOX)
    // ═════════════════════════════════════════════════════════

    private fun setupDecryptInputState() {
        binding.btnRefreshInbox.setOnClickListener { decryptFromInput() }
        binding.tvInboxStatus.text = "Enter sender's username, paste obfuscated text in the text field above, then tap Decrypt"
    }

    /**
     * Read obfuscated text from the HOST APP's text field, decrypt using
     * the sender username typed into et_sender_username.
     */
    private fun decryptFromInput() {
        val senderUsername = binding.etSenderUsername.text.toString().trim()
        if (senderUsername.isEmpty()) {
            binding.tvInboxStatus.text = "Enter the sender's username first"
            return
        }

        val obfuscatedText = binding.etEncryptedInput.text.toString().trim()
        if (obfuscatedText.isEmpty()) {
            binding.tvInboxStatus.text = "Paste the obfuscated text first"
            return
        }

        binding.tvInboxStatus.text = "⏳ Decrypting..."

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.decryptMessage(obfuscatedText, senderUsername)
            withContext(Dispatchers.Main) {
                result.onSuccess { plaintext ->
                    showState(STATE_DECRYPT)
                    binding.tvDecryptFrom.text = "From: $senderUsername"
                    binding.tvDecryptedText.text = plaintext
                    binding.tvDecryptStatus.text = "✅ Decrypted successfully"
                }.onFailure { e ->
                    binding.tvInboxStatus.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    // ═════════════════════════════════════════════════════════
    //  State 3: DECRYPT RESULT
    // ═════════════════════════════════════════════════════════

    private fun setupDecryptResultState() {
        binding.btnBackToInbox.text = "⬅ Back"
        binding.btnBackToInbox.setOnClickListener {
            showState(STATE_INBOX)
        }
    }

    // ═════════════════════════════════════════════════════════
    //  Helpers
    // ═════════════════════════════════════════════════════════

    private fun simplifyError(e: Throwable): String {
        val msg = e.message ?: "Unknown error"
        return when {
            msg.contains("ConnectException") || msg.contains("Failed to connect") ->
                "Cannot connect to server. Is it running?"
            msg.contains("wrong key") || msg.contains("tampered data") || msg.contains("InvalidTag") ->
                "Key mismatch. Clear DB and re-register both users (Bob first, then Alice)."
            msg.contains("No shared secret") || msg.contains("ephemeral key") ->
                "Missing key for decryption. Ensure sender sent first message correctly."
            msg.contains("401") || msg.contains("Unauthorized") ->
                "Invalid credentials"
            msg.contains("409") || msg.contains("Conflict") ->
                "User already exists — try Login instead"
            msg.contains("422") ->
                "Invalid input"
            else -> msg.take(120)
        }
    }
}
