package com.frogobox.appkeyboard.ui.keyboard.securemessaging

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.util.AttributeSet
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.inputmethod.ExtractedTextRequest
import android.widget.LinearLayout
import android.widget.TextView
import com.frogobox.appkeyboard.databinding.KeyboardSecureMessagingBinding
import com.frogobox.appkeyboard.data.repository.InboxMessage
import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import com.frogobox.appkeyboard.di.SecureKeyboardEntryPoint
import com.frogobox.libkeyboard.common.core.BaseKeyboard
import dagger.hilt.android.EntryPointAccessors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Secure Messaging Keyboard — Full E2EE + Steganographic Obfuscation
 *
 * Auth (login / register) is handled in the main app (SecureAuthActivity).
 * This panel only handles compose / inbox / decrypt when already logged in.
 *
 * Text input (search query, message text) is read from the host app's
 * text field via InputConnection — no EditTexts inside the IME panel.
 *
 * States (ViewFlipper indices):
 *   0 = NOT_LOGGED_IN  (instruction to open the app)
 *   1 = COMPOSE        (search user → create conversation → send encrypted)
 *   2 = INBOX          (list of obfuscated messages)
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

    // Conversation state for compose flow
    private var selectedRecipientId: String? = null
    private var selectedRecipientName: String? = null
    private var activeConversationId: String? = null

    // Cached inbox for decrypt flow
    private var cachedInbox: List<InboxMessage> = emptyList()

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

        try {
            // Decide initial state
            if (repo.isLoggedIn()) {
                showState(STATE_COMPOSE)
            } else {
                showState(STATE_NOT_LOGGED_IN)
            }
        } catch (e: Exception) {
            // Hilt not ready — default to not-logged-in
            showState(STATE_NOT_LOGGED_IN)
        }

        setupComposeState()
        setupInboxState()
        setupDecryptState()
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
            STATE_INBOX -> "📥 $username"
            STATE_DECRYPT -> "🔓 Decrypt"
            else -> "Secure Messaging"
        }

        // Toolbar nav buttons
        binding.btnInbox.setOnClickListener {
            showState(STATE_INBOX)
            refreshInbox()
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

    /** Read the current text from the host app's text field via InputConnection. */
    private fun readHostTextField(): String {
        return currentInputConnection?.let { ic ->
            ic.getExtractedText(ExtractedTextRequest(), 0)?.text?.toString()?.trim() ?: ""
        } ?: ""
    }

    private fun searchUser() {
        val query = readHostTextField()
        if (query.isEmpty()) {
            binding.tvSearchResult.visibility = View.VISIBLE
            binding.tvSearchResult.text = "Type a username in the text field above first"
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
        binding.btnStartConversation.isEnabled = false
        binding.tvSearchResult.text = "⏳ Creating conversation..."

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.createConversation(recipientId)
            withContext(Dispatchers.Main) {
                binding.btnStartConversation.isEnabled = true
                result.onSuccess { conv ->
                    activeConversationId = conv.conversationId
                    binding.composeArea.visibility = View.VISIBLE
                    binding.tvComposeLabel.text = "Messaging: $selectedRecipientName"
                    binding.tvSendStatus.text = ""
                    binding.scrollObfuscated.visibility = View.GONE
                    binding.tvSearchResult.text = "✅ Conversation ready"
                    binding.btnStartConversation.visibility = View.GONE
                }.onFailure { e ->
                    binding.tvSearchResult.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    private fun sendMessage() {
        val conversationId = activeConversationId ?: return
        val recipientId = selectedRecipientId ?: return

        // Read plaintext from the host app's input field
        val plaintext = readHostTextField()

        if (plaintext.isEmpty()) {
            binding.tvSendStatus.text = "Type a message in the text field first"
            return
        }

        binding.btnSend.isEnabled = false
        binding.tvSendStatus.text = "⏳ Encrypting & sending..."

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.sendMessage(conversationId, recipientId, plaintext)
            withContext(Dispatchers.Main) {
                binding.btnSend.isEnabled = true
                result.onSuccess { sendResult ->
                    // Replace input field text with obfuscated decoy
                    currentInputConnection?.apply {
                        deleteSurroundingText(plaintext.length, 0)
                        commitText(sendResult.obfuscatedText, 1)
                    }

                    binding.tvSendStatus.text = "✅ Sent! Decoy text placed in input field."
                    binding.scrollObfuscated.visibility = View.VISIBLE
                    binding.tvObfuscatedPreview.text =
                        "Decoy: \"${sendResult.obfuscatedText}\"\n\nMessage ID: ${sendResult.messageId.take(8)}..."
                }.onFailure { e ->
                    binding.tvSendStatus.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    private fun resetComposeState() {
        selectedRecipientId = null
        selectedRecipientName = null
        activeConversationId = null
    }

    // ═════════════════════════════════════════════════════════
    //  State 2: INBOX
    // ═════════════════════════════════════════════════════════

    private fun setupInboxState() {
        binding.btnRefreshInbox.setOnClickListener { refreshInbox() }
    }

    private fun refreshInbox() {
        binding.tvInboxStatus.text = "⏳ Loading..."
        binding.inboxContainer.removeAllViews()

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.getInbox()
            withContext(Dispatchers.Main) {
                result.onSuccess { messages ->
                    cachedInbox = messages
                    binding.inboxContainer.removeAllViews()

                    if (messages.isEmpty()) {
                        binding.tvInboxStatus.text = "No messages yet"
                        return@onSuccess
                    }

                    binding.tvInboxStatus.text = "${messages.size} message(s)"

                    for (msg in messages) {
                        binding.inboxContainer.addView(createMessageCard(msg))
                    }
                }.onFailure { e ->
                    binding.tvInboxStatus.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    /**
     * Creates a tappable card for a single inbox message.
     * Shows sender + obfuscated preview. Tap → reveal + decrypt.
     */
    private fun createMessageCard(msg: InboxMessage): View {
        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 12, 16, 12)
            setBackgroundColor(Color.parseColor("#F5F5F5"))
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            params.bottomMargin = 8
            layoutParams = params
            isClickable = true
            isFocusable = true
            setBackgroundResource(android.R.drawable.list_selector_background)
        }

        val senderLine = TextView(context).apply {
            text = "From: ${msg.senderUsername}"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#212121"))
        }

        val preview = TextView(context).apply {
            text = msg.obfuscatedText.take(80) + if (msg.obfuscatedText.length > 80) "…" else ""
            textSize = 12f
            setTextColor(Color.parseColor("#616161"))
            maxLines = 2
        }

        val timeLine = TextView(context).apply {
            text = msg.createdAt.take(19).replace("T", " ")
            textSize = 10f
            setTextColor(Color.parseColor("#9E9E9E"))
            gravity = Gravity.END
        }

        card.addView(senderLine)
        card.addView(preview)
        card.addView(timeLine)

        card.setOnClickListener {
            revealAndDecrypt(msg)
        }

        return card
    }

    // ═════════════════════════════════════════════════════════
    //  State 3: DECRYPT
    // ═════════════════════════════════════════════════════════

    private fun setupDecryptState() {
        binding.btnBackToInbox.setOnClickListener {
            showState(STATE_INBOX)
            refreshInbox()
        }
    }

    private fun revealAndDecrypt(msg: InboxMessage) {
        showState(STATE_DECRYPT)
        binding.tvDecryptFrom.text = "From: ${msg.senderUsername} • ${msg.createdAt.take(19).replace("T", " ")}"
        binding.tvDecryptedText.text = "⏳ Revealing & decrypting..."
        binding.tvDecryptStatus.text = ""

        GlobalScope.launch(Dispatchers.IO) {
            val result = repo.revealAndDecrypt(
                messageId = msg.messageId,
                conversationId = msg.conversationId,
                senderId = msg.senderId
            )
            withContext(Dispatchers.Main) {
                result.onSuccess { plaintext ->
                    binding.tvDecryptedText.text = plaintext
                    binding.tvDecryptStatus.text = "✅ Decrypted successfully"
                }.onFailure { e ->
                    binding.tvDecryptedText.text = ""
                    binding.tvDecryptStatus.text = "❌ ${simplifyError(e)}"
                }
            }
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
