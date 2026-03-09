package com.frogobox.appkeyboard.ui.keyboard.securemessaging

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.text.Editable
import android.text.TextWatcher
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.inputmethod.ExtractedTextRequest
import android.widget.LinearLayout
import android.widget.Toast
import com.frogobox.appkeyboard.R
import com.frogobox.appkeyboard.databinding.KeyboardSecureMessagingBinding
import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import com.frogobox.appkeyboard.di.SecureKeyboardEntryPoint
import com.frogobox.appkeyboard.ui.secure.SecureAuthActivity
import com.frogobox.libkeyboard.common.core.BaseKeyboard
import dagger.hilt.android.EntryPointAccessors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Secure Messaging Keyboard — Full E2EE + Steganographic Obfuscation
 *
 * States (ViewFlipper indices):
 *   0 = NOT_LOGGED_IN
 *   1 = COMPOSE (search user -> create session -> send encrypted)
 *   2 = DECRYPT (paste encrypted text -> deobfuscate -> decrypt)
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

        private const val PREFS_NAME = "secure_active_session"
        private const val KEY_SESSION_ID = "session_id"
        private const val KEY_RECIPIENT_NAME = "recipient_name"
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

    private var selectedRecipientId: String? = null
    private var selectedRecipientName: String? = null
    private var activeSessionId: String? = null
    private var clipboardText: String? = null
    private var uiInitialized = false

    private fun persistActiveSession(sessionId: String, recipientName: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString(KEY_SESSION_ID, sessionId)
            .putString(KEY_RECIPIENT_NAME, recipientName)
            .apply()
    }

    private fun clearPersistedSession() {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
    }

    override fun setupViewBinding(
        inflater: LayoutInflater,
        parent: LinearLayout
    ): KeyboardSecureMessagingBinding {
        return KeyboardSecureMessagingBinding.inflate(LayoutInflater.from(context), this, true)
    }

    override fun initUI() {
        super.initUI()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (uiInitialized) return
        uiInitialized = true

        setupLoginState()
        setupComposeState()
        setupDecryptInputState()
        setupDecryptResultState()
        refreshAuthState()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        if (changedView == this && visibility == View.VISIBLE && uiInitialized) {
            refreshAuthState()
        }
    }

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

    // ═══════════════════════════════════════════════════════════
    //  State Management
    // ═══════════════════════════════════════════════════════════

    private fun showState(state: Int) {
        val loggedIn = try { repo.isLoggedIn() } catch (_: Exception) { false }

        if (!loggedIn && state != STATE_NOT_LOGGED_IN) {
            binding.viewFlipper.displayedChild = STATE_NOT_LOGGED_IN
            binding.btnInbox.visibility = View.GONE
            binding.btnCompose.visibility = View.GONE
            binding.btnLogout.visibility = View.GONE
            binding.tvToolbarTitle.text = context.getString(R.string.secure_title)
            return
        }

        setFlipperAnimation(state)
        binding.viewFlipper.displayedChild = state

        if (state == STATE_INBOX) {
            autoPasteClipboard()
        }

        binding.btnInbox.visibility = if (loggedIn) View.VISIBLE else View.GONE
        binding.btnCompose.visibility = if (loggedIn) View.VISIBLE else View.GONE
        binding.btnLogout.visibility = if (loggedIn) View.VISIBLE else View.GONE

        val isCompose = state == STATE_COMPOSE
        val isInbox = state == STATE_INBOX || state == STATE_DECRYPT
        binding.btnCompose.setBackgroundResource(
            if (isCompose) R.drawable.bg_tab_active_new else R.drawable.bg_tab_inactive_new
        )
        binding.btnInbox.setBackgroundResource(
            if (isInbox) R.drawable.bg_tab_active_new else R.drawable.bg_tab_inactive_new
        )

        val username = repo.getUsername() ?: context.getString(R.string.secure_title)
        binding.tvToolbarTitle.text = when (state) {
            STATE_NOT_LOGGED_IN -> context.getString(R.string.secure_title)
            STATE_COMPOSE -> username
            STATE_INBOX, STATE_DECRYPT -> context.getString(R.string.secure_tab_decrypt)
            else -> context.getString(R.string.secure_title)
        }

        binding.btnInbox.setOnClickListener { showState(STATE_INBOX) }
        binding.btnCompose.setOnClickListener { showState(STATE_COMPOSE) }
        binding.btnLogout.setOnClickListener {
            repo.logout()
            resetComposeState()
            showState(STATE_NOT_LOGGED_IN)
        }
    }

    private fun setFlipperAnimation(targetState: Int) {
        val currentState = binding.viewFlipper.displayedChild
        if (currentState == targetState) return

        if (targetState > currentState) {
            binding.viewFlipper.setInAnimation(context, R.anim.slide_in_right)
            binding.viewFlipper.setOutAnimation(context, R.anim.slide_out_left)
        } else {
            binding.viewFlipper.setInAnimation(context, R.anim.slide_in_left)
            binding.viewFlipper.setOutAnimation(context, R.anim.slide_out_right)
        }
    }

    private fun autoPasteClipboard() {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            if (!clip.isNullOrBlank()) {
                clipboardText = clip
                binding.tvClipboardStatus.text =
                    context.getString(R.string.secure_clipboard_ready, clip.length)
                binding.tvClipboardStatus.setTextColor(
                    context.getColor(R.color.secure_text_success)
                )
            } else {
                clipboardText = null
                binding.tvClipboardStatus.text =
                    context.getString(R.string.secure_clipboard_empty)
                binding.tvClipboardStatus.setTextColor(
                    context.getColor(R.color.secure_text_warning)
                )
            }
        } catch (_: Exception) {
            clipboardText = null
        }

        // Auto-fill sender from persisted session
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val savedRecipient = prefs.getString(KEY_RECIPIENT_NAME, null)
        if (!savedRecipient.isNullOrEmpty()) {
            binding.etSenderUsername.setText(savedRecipient)
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  State 0: NOT LOGGED IN
    // ═══════════════════════════════════════════════════════════

    private fun setupLoginState() {
        binding.btnOpenLogin.setOnClickListener {
            val intent = Intent(context, SecureAuthActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  State 1: COMPOSE
    // ═══════════════════════════════════════════════════════════

    private fun setupComposeState() {
        binding.btnSearch.setOnClickListener { searchUser() }
        binding.btnStartConversation.setOnClickListener { startConversation() }
        binding.btnSend.setOnClickListener { sendMessage() }

        binding.btnClearSearch.setOnClickListener {
            binding.etUsername.text?.clear()
            binding.btnClearSearch.visibility = View.GONE
            binding.tvSearchResult.visibility = View.GONE
            binding.btnStartConversation.visibility = View.GONE
        }

        binding.etUsername.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                binding.btnClearSearch.visibility =
                    if (s.isNullOrEmpty()) View.GONE else View.VISIBLE
            }
        })

        binding.btnCopyObfuscated.setOnClickListener {
            val text = binding.tvObfuscatedPreview.text.toString()
            if (text.isNotEmpty()) {
                copyToClipboard(text)
            }
        }
    }

    private fun searchUser() {
        val query = binding.etUsername.text.toString().trim()
        if (query.isEmpty()) {
            binding.tvSearchResult.visibility = View.VISIBLE
            binding.tvSearchResult.text = context.getString(R.string.secure_search_empty)
            return
        }

        setSearchLoading(true)
        binding.tvSearchResult.visibility = View.VISIBLE
        binding.tvSearchResult.text = context.getString(R.string.secure_searching)
        binding.btnStartConversation.visibility = View.GONE
        binding.composeArea.visibility = View.GONE

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.searchUsers(query)
            withContext(Dispatchers.Main) {
                setSearchLoading(false)
                result.onSuccess { users ->
                    val others = users.filter { it.userId != repo.getUserId() }
                    if (others.isEmpty()) {
                        binding.tvSearchResult.text =
                            context.getString(R.string.secure_no_users_found, query)
                    } else {
                        val user = others.first()
                        selectedRecipientId = user.userId
                        selectedRecipientName = user.username
                        binding.tvSearchResult.text =
                            context.getString(R.string.secure_found_user, user.username)
                        binding.btnStartConversation.visibility = View.VISIBLE
                        binding.btnStartConversation.text =
                            context.getString(R.string.secure_start_conv_with, user.username)
                    }
                }.onFailure { e ->
                    binding.tvSearchResult.text = simplifyError(e)
                    binding.tvSearchResult.setTextColor(
                        context.getColor(R.color.secure_text_danger)
                    )
                }
            }
        }
    }

    private fun setSearchLoading(loading: Boolean) {
        binding.progressSearch.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnSearch.isEnabled = !loading
    }

    private fun startConversation() {
        val recipientId = selectedRecipientId ?: return
        val recipientName = selectedRecipientName ?: return
        binding.btnStartConversation.isEnabled = false
        binding.tvSearchResult.text = context.getString(R.string.secure_session_creating)

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.createSession(recipientName, recipientId)
            withContext(Dispatchers.Main) {
                binding.btnStartConversation.isEnabled = true
                result.onSuccess { sessionInfo ->
                    activeSessionId = sessionInfo.sessionId
                    persistActiveSession(sessionInfo.sessionId, selectedRecipientName ?: "")
                    binding.composeArea.visibility = View.VISIBLE
                    binding.tvComposeLabel.text =
                        context.getString(R.string.secure_messaging_label, selectedRecipientName)
                    binding.tvSendStatus.text = ""
                    binding.obfuscatedContainer.visibility = View.GONE
                    binding.tvSearchResult.text = context.getString(R.string.secure_session_ready)
                    binding.tvSearchResult.setTextColor(
                        context.getColor(R.color.secure_text_success)
                    )
                    binding.btnStartConversation.visibility = View.GONE
                }.onFailure { e ->
                    binding.tvSearchResult.text = simplifyError(e)
                    binding.tvSearchResult.setTextColor(
                        context.getColor(R.color.secure_text_danger)
                    )
                }
            }
        }
    }

    private fun sendMessage() {
        val sessionId = activeSessionId ?: return
        val ic = currentInputConnection

        if (ic == null) {
            binding.tvSendStatus.text = context.getString(R.string.secure_no_text_field)
            binding.tvSendStatus.setTextColor(context.getColor(R.color.secure_text_danger))
            return
        }

        val extracted = ic.getExtractedText(ExtractedTextRequest(), 0)
        val plaintext = extracted?.text?.toString()?.trim() ?: ""

        if (plaintext.isEmpty()) {
            binding.tvSendStatus.text = context.getString(R.string.secure_type_message_hint)
            return
        }

        setSendLoading(true)
        binding.tvSendStatus.text = context.getString(R.string.secure_encrypting)
        binding.tvSendStatus.setTextColor(context.getColor(R.color.secure_text_secondary))

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.sendMessage(sessionId, selectedRecipientName ?: "", plaintext)
            withContext(Dispatchers.Main) {
                setSendLoading(false)
                result.onSuccess { sendResult ->
                    ic.apply {
                        performContextMenuAction(android.R.id.selectAll)
                        commitText(sendResult.obfuscatedText, 1)
                    }

                    binding.tvSendStatus.text = context.getString(R.string.secure_encrypted_done)
                    binding.tvSendStatus.setTextColor(
                        context.getColor(R.color.secure_text_success)
                    )
                    binding.obfuscatedContainer.visibility = View.VISIBLE
                    binding.tvObfuscatedPreview.text = sendResult.obfuscatedText
                }.onFailure { e ->
                    binding.tvSendStatus.text = simplifyError(e)
                    binding.tvSendStatus.setTextColor(
                        context.getColor(R.color.secure_text_danger)
                    )
                }
            }
        }
    }

    private fun setSendLoading(loading: Boolean) {
        binding.progressSend.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnSend.isEnabled = !loading
    }

    private fun resetComposeState() {
        selectedRecipientId = null
        selectedRecipientName = null
        activeSessionId = null
        clearPersistedSession()
    }

    // ═══════════════════════════════════════════════════════════
    //  State 2: DECRYPT
    // ═══════════════════════════════════════════════════════════

    private fun setupDecryptInputState() {
        binding.btnRefreshInbox.setOnClickListener { decryptFromInput() }
        binding.tvInboxStatus.text = context.getString(R.string.secure_enter_sender)
    }

    private fun decryptFromInput() {
        val senderUsername = binding.etSenderUsername.text.toString().trim()
        if (senderUsername.isEmpty()) {
            binding.tvInboxStatus.text = context.getString(R.string.secure_enter_sender_first)
            binding.tvInboxStatus.setTextColor(context.getColor(R.color.secure_text_warning))
            return
        }

        val obfuscatedText = clipboardText?.trim()
        if (obfuscatedText.isNullOrEmpty()) {
            binding.tvInboxStatus.text = context.getString(R.string.secure_clipboard_empty)
            binding.tvInboxStatus.setTextColor(context.getColor(R.color.secure_text_warning))
            return
        }

        setDecryptLoading(true)
        binding.tvInboxStatus.text = context.getString(R.string.secure_decrypting_hint)
        binding.tvInboxStatus.setTextColor(context.getColor(R.color.secure_text_secondary))

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.decryptMessage(obfuscatedText, senderUsername)
            withContext(Dispatchers.Main) {
                setDecryptLoading(false)
                result.onSuccess { plaintext ->
                    showState(STATE_DECRYPT)
                    binding.tvDecryptFrom.text =
                        context.getString(R.string.secure_messaging_label, senderUsername)
                            .replace("Messaging:", "From:")
                    binding.tvDecryptedText.text = plaintext
                    binding.tvDecryptStatus.text =
                        context.getString(R.string.secure_decrypted_ok)
                    binding.tvDecryptStatus.setTextColor(
                        context.getColor(R.color.secure_text_success)
                    )
                }.onFailure { e ->
                    binding.tvInboxStatus.text = simplifyError(e)
                    binding.tvInboxStatus.setTextColor(
                        context.getColor(R.color.secure_text_danger)
                    )
                }
            }
        }
    }

    private fun setDecryptLoading(loading: Boolean) {
        binding.progressDecrypt.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnRefreshInbox.isEnabled = !loading
    }

    // ═══════════════════════════════════════════════════════════
    //  State 3: DECRYPT RESULT
    // ═══════════════════════════════════════════════════════════

    private fun setupDecryptResultState() {
        binding.btnBackToInbox.setOnClickListener {
            showState(STATE_INBOX)
        }

        binding.btnCopyDecrypted.setOnClickListener {
            val text = binding.tvDecryptedText.text.toString()
            if (text.isNotEmpty()) {
                copyToClipboard(text)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════

    private fun copyToClipboard(text: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Secure Message", text))
        Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
    }

    private fun simplifyError(e: Throwable): String {
        val msg = e.message ?: "Unknown error"
        return when {
            msg.contains("ConnectException") || msg.contains("Failed to connect") ->
                "Cannot connect to server. Is it running?"
            msg.contains("wrong key") || msg.contains("tampered data") || msg.contains("InvalidTag") ->
                "Key mismatch. Clear DB and re-register both users."
            msg.contains("No shared secret") || msg.contains("ephemeral key") ->
                "Missing key for decryption."
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
