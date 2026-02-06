package com.frogobox.appkeyboard.ui.secure

import android.os.Bundle
import android.view.View
import com.frogobox.appkeyboard.common.base.BaseActivity
import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import com.frogobox.appkeyboard.databinding.ActivitySecureAuthBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Full-screen Activity for Secure Messaging login / registration.
 *
 * This runs inside the normal app (not the IME window), so the system
 * keyboard works normally for typing username & password.
 *
 * Auth state is persisted in EncryptedSharedPreferences via [SecureMessagingRepository],
 * so the keyboard IME panel can read it immediately.
 */
@AndroidEntryPoint
class SecureAuthActivity : BaseActivity<ActivitySecureAuthBinding>() {

    @Inject
    lateinit var repo: SecureMessagingRepository

    override fun setupViewBinding(): ActivitySecureAuthBinding =
        ActivitySecureAuthBinding.inflate(layoutInflater)

    override fun initView() {
        super.initView()

        refreshUI()

        binding.btnLogin.setOnClickListener { doAuth(isRegister = false) }
        binding.btnRegister.setOnClickListener { doAuth(isRegister = true) }
        binding.btnLogout.setOnClickListener {
            repo.logout()
            refreshUI()
            binding.tvStatus.text = "Logged out"
        }
    }

    private fun doAuth(isRegister: Boolean) {
        val username = binding.etUsername.text.toString().trim()
        val password = binding.etPassword.text.toString().trim()

        if (username.isEmpty() || password.isEmpty()) {
            binding.tvStatus.text = "Please enter both username and password"
            return
        }

        val label = if (isRegister) "Registering" else "Logging in"
        binding.tvStatus.text = "⏳ $label..."
        setButtonsEnabled(false)

        GlobalScope.launch(Dispatchers.IO) {
            val result = if (isRegister) {
                repo.register(username, password)
            } else {
                repo.login(username, password)
            }

            withContext(Dispatchers.Main) {
                setButtonsEnabled(true)
                result.onSuccess {
                    binding.tvStatus.text = "✅ Success!"
                    binding.etUsername.text?.clear()
                    binding.etPassword.text?.clear()
                    refreshUI()
                }.onFailure { e ->
                    binding.tvStatus.text = "❌ ${simplifyError(e)}"
                }
            }
        }
    }

    private fun refreshUI() {
        if (repo.isLoggedIn()) {
            binding.cardLoggedIn.visibility = View.VISIBLE
            binding.tvLoggedInUser.text = repo.getUsername() ?: "—"
            binding.btnLogin.isEnabled = false
            binding.btnRegister.isEnabled = false
            binding.etUsername.isEnabled = false
            binding.etPassword.isEnabled = false
        } else {
            binding.cardLoggedIn.visibility = View.GONE
            binding.btnLogin.isEnabled = true
            binding.btnRegister.isEnabled = true
            binding.etUsername.isEnabled = true
            binding.etPassword.isEnabled = true
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        binding.btnLogin.isEnabled = enabled
        binding.btnRegister.isEnabled = enabled
    }

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
            else -> msg.take(150)
        }
    }
}
