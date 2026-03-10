package com.frogobox.appkeyboard.ui.keyboard.securemessaging

import android.content.Context
import android.content.Intent
import android.text.Editable
import android.text.TextWatcher
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
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
 * Secure Messaging Keyboard — Session Management Only
 *
 * States (ViewFlipper indices):
 *   0 = NOT_LOGGED_IN
 *   1 = SESSION_MGMT (search user -> create session)
 *
 * Encryption and decryption are handled by inline keyboard header buttons
 * in KeyboardIME (SECURE_ENCRYPT / SECURE_DECRYPT).
 */
class SecureMessagingKeyboard(
    context: Context,
    attrs: AttributeSet?,
) : BaseKeyboard<KeyboardSecureMessagingBinding>(context, attrs) {

    companion object {
        private const val STATE_NOT_LOGGED_IN = 0
        private const val STATE_SESSION_MGMT = 1

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
        setupSessionMgmtState()
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
                showState(STATE_SESSION_MGMT)
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
            binding.btnLogout.visibility = View.GONE
            binding.tvToolbarTitle.text = context.getString(R.string.secure_title)
            return
        }

        setFlipperAnimation(state)
        binding.viewFlipper.displayedChild = state

        binding.btnLogout.visibility = if (loggedIn) View.VISIBLE else View.GONE

        val username = repo.getUsername() ?: context.getString(R.string.secure_title)
        binding.tvToolbarTitle.text = when (state) {
            STATE_NOT_LOGGED_IN -> context.getString(R.string.secure_title)
            STATE_SESSION_MGMT -> username
            else -> context.getString(R.string.secure_title)
        }

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
    //  State 1: SESSION MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    private fun setupSessionMgmtState() {
        binding.btnSearch.setOnClickListener { searchUser() }
        binding.btnStartConversation.setOnClickListener { startConversation() }

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

    private fun resetComposeState() {
        selectedRecipientId = null
        selectedRecipientName = null
        activeSessionId = null
        clearPersistedSession()
    }

    // ═══════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════

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
