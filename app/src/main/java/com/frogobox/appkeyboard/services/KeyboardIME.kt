package com.frogobox.appkeyboard.services

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.ExtractedTextRequest
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.Toast
import com.frogobox.appkeyboard.R
import com.frogobox.appkeyboard.databinding.ItemKeyboardHeaderBinding
import com.frogobox.appkeyboard.databinding.KeyboardImeBinding
import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import com.frogobox.appkeyboard.di.SecureKeyboardEntryPoint
import com.frogobox.appkeyboard.model.KeyboardFeatureModel
import com.frogobox.appkeyboard.model.KeyboardFeatureType
import com.frogobox.appkeyboard.model.ThemeType
import com.frogobox.appkeyboard.ui.main.MainActivity
import com.frogobox.libkeyboard.common.core.BaseKeyboardIME
import com.frogobox.recycler.core.FrogoRecyclerNotifyListener
import com.frogobox.recycler.core.IFrogoBindingAdapter
import com.frogobox.recycler.ext.injectorBinding
import com.frogobox.sdk.delegate.preference.PreferenceDelegates
import com.frogobox.sdk.ext.getColorExt
import com.frogobox.sdk.ext.gone
import com.frogobox.sdk.ext.invisible
import com.frogobox.sdk.ext.visible
import com.frogobox.appkeyboard.core.DecryptCaptureState
import dagger.hilt.android.AndroidEntryPoint
import dagger.hilt.android.EntryPointAccessors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject


@AndroidEntryPoint
class KeyboardIME : BaseKeyboardIME<KeyboardImeBinding>() {

    companion object {
        private const val SECURE_SESSION_PREFS = "secure_active_session"
        private const val KEY_RECIPIENT_NAME = "recipient_name"
        private const val KEY_SESSION_ID = "session_id"
        private const val KEY_DECRYPT_FROM_CLIPBOARD = "decrypt_from_clipboard"
    }

    @Inject
    lateinit var pref: PreferenceDelegates

    @Inject
    lateinit var keyboardUtil: KeyboardUtil

    private val secureRepo: SecureMessagingRepository by lazy {
        EntryPointAccessors.fromApplication(
            applicationContext,
            SecureKeyboardEntryPoint::class.java
        ).secureMessagingRepository()
    }

    override fun setupViewBinding(): KeyboardImeBinding {
        return KeyboardImeBinding.inflate(LayoutInflater.from(this), null, false)
    }

    override fun setupTheme() {
        binding?.apply {

            val background = pref.getPrefInt(
                KeyboardUtil.KEYBOARD_COLOR,
                R.color.color_bg_keyboard_default
            )

            val backgroundType = ThemeType.valueOf(
                pref.getPrefString(
                    KeyboardUtil.KEYBOARD_COLOR_TYPE,
                    ThemeType.COLOR.name
                )
            )

            when (backgroundType) {
                ThemeType.COLOR -> {
                    ivBackgroundKeyboard.setBackgroundColor(getColorExt(background))
                }
                ThemeType.IMAGE -> {
                    ivBackgroundKeyboard.setImageResource(background)
                }
            }
        }
    }

    override fun initialSetupKeyboard() {
        binding?.keyboardMain?.setKeyboard(keyboard!!)
    }

    override fun setupBinding() {
        super.setupBinding()
        binding?.apply {
            keyboardMain.mOnKeyboardActionListener = this@KeyboardIME
            keyboardEmoji.mOnKeyboardActionListener = this@KeyboardIME
        }

    }

    override fun invalidateKeyboard() {
        binding?.keyboardAutotext?.initData()
        setupFeatureKeyboard()
    }

    override fun initCurrentInputConnection() {
        binding?.apply {
            keyboardAutotext.setInputConnection(currentInputConnection)
            keyboardNews.setInputConnection(currentInputConnection)
            keyboardMoview.setInputConnection(currentInputConnection)
            keyboardWebview.setInputConnection(currentInputConnection)
            keyboardForm.setInputConnection(currentInputConnection)
            keyboardEmoji.setInputConnection(currentInputConnection)
            keyboardTemplateText.setInputConnection(currentInputConnection)
            keyboardCompression.setInputConnection(currentInputConnection)
            keyboardSecureMessaging.setInputConnection(currentInputConnection)
        }
    }

    override fun hideMainKeyboard() {
        binding?.apply {
            keyboardMain.invisible()
            keyboardHeader.invisible()
        }
    }

    override fun showMainKeyboard() {
        binding?.apply {
            keyboardMain.visible()
            if (keyboardUtil.menuKeyboard().isEmpty()) {
                keyboardHeader.gone()
            } else {
                keyboardHeader.visible()
            }
            keyboardAutotext.gone()
            keyboardNews.gone()
            keyboardMoview.gone()
            keyboardWebview.gone()
            keyboardForm.gone()
            keyboardEmoji.gone()
            keyboardCompression.gone()
            keyboardSecureMessaging.gone()
            keyboardDemo.gone()
            keyboardEmoji.binding.emojiList.scrollToPosition(0)
        }
    }

    override fun showOnlyKeyboard() {
        binding?.keyboardMain?.visible()
    }

    override fun hideOnlyKeyboard() {
        binding?.keyboardMain?.gone()
    }

    override fun EditText.showKeyboardExt() {
        setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) {
                showOnlyKeyboard()
            }
        }
        setOnClickListener {
            showOnlyKeyboard()
        }
    }

    override fun initBackToMainKeyboard() {
        binding?.apply {
            keyboardAutotext.binding.toolbarBack.setOnClickListener {
                keyboardAutotext.gone()
                showMainKeyboard()
            }

            keyboardNews.binding.toolbarBack.setOnClickListener {
                keyboardNews.gone()
                showMainKeyboard()
            }

            keyboardMoview.binding.toolbarBack.setOnClickListener {
                keyboardMoview.gone()
                showMainKeyboard()
            }

            keyboardWebview.binding.toolbarBack.setOnClickListener {
                keyboardWebview.gone()
                showMainKeyboard()
            }

            keyboardForm.binding.toolbarBack.setOnClickListener {
                keyboardForm.gone()
                showMainKeyboard()
            }

            keyboardEmoji.binding.toolbarBack.setOnClickListener {
                keyboardEmoji.gone()
                keyboardEmoji.binding.emojiList.scrollToPosition(0)
                showMainKeyboard()
            }

            keyboardTemplateText.binding.toolbarBack.setOnClickListener {
                keyboardTemplateText.gone()
                showMainKeyboard()
            }

            keyboardCompression.binding.toolbarBack.setOnClickListener {
                keyboardCompression.gone()
                showMainKeyboard()
            }

            keyboardSecureMessaging.binding.btnBack.setOnClickListener {
                keyboardSecureMessaging.gone()
                showMainKeyboard()
            }

            keyboardDemo.binding.btnBack.setOnClickListener {
                keyboardDemo.gone()
                showMainKeyboard()
            }

        }
    }

    override fun setupFeatureKeyboard() {
        val maxMenu = 4
        val gridSize = if (keyboardUtil.menuKeyboard().size <= maxMenu) {
            keyboardUtil.menuKeyboard().size
        } else if (keyboardUtil.menuKeyboard().size.mod(maxMenu) == 0) {
            maxMenu
        } else {
            maxMenu + 1
        }

        binding?.apply {
            if (keyboardUtil.menuKeyboard().isEmpty()) {
                keyboardHeader.gone()
            } else {
                keyboardHeader.visible()
                keyboardHeader.injectorBinding<KeyboardFeatureModel, ItemKeyboardHeaderBinding>()
                    .addData(keyboardUtil.menuKeyboard()).addCallback(object :
                        IFrogoBindingAdapter<KeyboardFeatureModel, ItemKeyboardHeaderBinding> {

                            override fun areContentsTheSame(
                            oldItem: KeyboardFeatureModel,
                            newItem: KeyboardFeatureModel
                        ): Boolean {
                            return oldItem == newItem
                        }

                        override fun areItemsTheSame(
                            oldItem: KeyboardFeatureModel,
                            newItem: KeyboardFeatureModel
                        ): Boolean {
                            return oldItem.id == newItem.id
                        }

                        override fun setViewBinding(parent: ViewGroup): ItemKeyboardHeaderBinding {
                            return ItemKeyboardHeaderBinding.inflate(
                                LayoutInflater.from(parent.context), parent, false
                            )
                        }

                        override fun setupInitComponent(
                            binding: ItemKeyboardHeaderBinding,
                            data: KeyboardFeatureModel,
                            position: Int,
                            notifyListener: FrogoRecyclerNotifyListener<KeyboardFeatureModel>,
                        ) {
                            binding.ivIcon.setImageResource(data.icon)
                            binding.tvTitle.text = data.text

                            if (getStateToggle(data.id)) {
                                binding.root.visible()
                            } else {
                                binding.root.gone()
                            }

                        }

                        override fun onItemClicked(
                            binding: ItemKeyboardHeaderBinding,
                            data: KeyboardFeatureModel,
                            position: Int,
                            notifyListener: FrogoRecyclerNotifyListener<KeyboardFeatureModel>,
                        ) {

                            when (KeyboardFeatureType.from(data.id)) {
                                KeyboardFeatureType.NEWS -> {
                                    hideMainKeyboard()
                                    keyboardNews.visible()
                                }

                                KeyboardFeatureType.MOVIE -> {
                                    hideMainKeyboard()
                                    keyboardMoview.visible()
                                }

                                KeyboardFeatureType.WEB -> {
                                    keyboardHeader.gone()
                                    keyboardWebview.visible()
                                }

                                KeyboardFeatureType.FORM -> {
                                    keyboardHeader.gone()
                                    keyboardForm.visible()
                                    keyboardForm.binding.etText.showKeyboardExt()
                                    keyboardForm.binding.etText2.showKeyboardExt()
                                    keyboardForm.binding.etText3.showKeyboardExt()

                                    keyboardForm.setOnClickListener {
                                        hideOnlyKeyboard()
                                    }
                                }

                                KeyboardFeatureType.AUTO_TEXT -> {
                                    hideMainKeyboard()
                                    keyboardAutotext.visible()
                                }

                                KeyboardFeatureType.TEMPLATE_TEXT_GAME -> {
                                    hideMainKeyboard()
                                    keyboardTemplateText.setupTemplateTextType(KeyboardFeatureType.TEMPLATE_TEXT_GAME)
                                    keyboardTemplateText.visible()
                                }

                                KeyboardFeatureType.TEMPLATE_TEXT_APP -> {
                                    hideMainKeyboard()
                                    keyboardTemplateText.setupTemplateTextType(KeyboardFeatureType.TEMPLATE_TEXT_APP)
                                    keyboardTemplateText.visible()
                                }

                                KeyboardFeatureType.TEMPLATE_TEXT_SALE -> {
                                    hideMainKeyboard()
                                    keyboardTemplateText.setupTemplateTextType(KeyboardFeatureType.TEMPLATE_TEXT_SALE)
                                    keyboardTemplateText.visible()
                                }

                                KeyboardFeatureType.TEMPLATE_TEXT_LOVE -> {
                                    hideMainKeyboard()
                                    keyboardTemplateText.setupTemplateTextType(KeyboardFeatureType.TEMPLATE_TEXT_LOVE)
                                    keyboardTemplateText.visible()
                                }

                                KeyboardFeatureType.TEMPLATE_TEXT_GREETING -> {
                                    hideMainKeyboard()
                                    keyboardTemplateText.setupTemplateTextType(KeyboardFeatureType.TEMPLATE_TEXT_GREETING)
                                    keyboardTemplateText.visible()
                                }

                                KeyboardFeatureType.COMPRESSION -> {
                                    hideMainKeyboard()
                                    keyboardCompression.visible()
                                }

                                KeyboardFeatureType.SECURE_MESSAGING -> {
                                    openSecureSessionPanel()
                                }

                                KeyboardFeatureType.SECURE_ENCRYPT -> {
                                    handleEncryptAction()
                                }

                                KeyboardFeatureType.SECURE_DECRYPT -> {
                                    handleDecryptAction()
                                }

                                KeyboardFeatureType.DEMO -> {
                                    hideMainKeyboard()
                                    keyboardDemo.visible()
                                    keyboardDemo.setInputConnection(currentInputConnection)
                                }

                                KeyboardFeatureType.CHANGE_KEYBOARD -> {
                                    (getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager).showInputMethodPicker()
                                }

                                KeyboardFeatureType.SETTING -> {
                                    binding.root.context.startActivity(Intent(
                                        binding.root.context, MainActivity::class.java
                                    ).apply {
                                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    })
                                }

                            }

                        }

                    }).createLayoutGrid(gridSize).build()
            }
        }
    }


    override fun onKey(code: Int) {
        val formView = binding?.keyboardForm
        var inputConnection = currentInputConnection

        if (formView?.visibility == View.VISIBLE) {
            val et1 = formView.binding.etText
            val et1Connection = et1.onCreateInputConnection(EditorInfo())

            val et2 = formView.binding.etText2
            val et2Connection = et2.onCreateInputConnection(EditorInfo())

            val et3 = formView.binding.etText3
            val et3Connection = et3.onCreateInputConnection(EditorInfo())

            if (et1.isFocused) {
                inputConnection = et1Connection
            } else if (et2.isFocused) {
                inputConnection = et2Connection
            } else if (et3.isFocused) {
                inputConnection = et3Connection
            }

        } else if (binding?.keyboardSecureMessaging?.visibility == View.VISIBLE) {
            val etUser = binding?.keyboardSecureMessaging?.binding?.etUsername

            if (etUser?.isFocused == true) {
                inputConnection = etUser.onCreateInputConnection(EditorInfo())
            }
        } else if (binding?.keyboardWebview?.visibility == View.VISIBLE) {
            inputConnection =
                binding?.keyboardWebview?.binding?.webview?.onCreateInputConnection(EditorInfo())
        } else {
            inputConnection = currentInputConnection
        }
        onKeyExt(code, inputConnection)
    }

    override fun initView() {
        setupFeatureKeyboard()
        initBackToMainKeyboard()
    }

    override fun invalidateAllKeys() {
        binding?.keyboardMain?.invalidateAllKeys()
    }

    
    override fun runEmojiBoard() {
        binding?.keyboardEmoji?.visible()
        binding?.keyboardMain?.invisible()
        binding?.keyboardHeader?.gone()
        binding?.keyboardEmoji?.openEmojiPalette()
    }

    override fun getKeyboardLayoutXML(): Int {
        return pref.getPrefInt(
            KeyboardUtil.KEYBOARD_TYPE, com.frogobox.libkeyboard.R.xml.keys_letters_qwerty
        )
    }

    private fun getStateToggle(key: String): Boolean {
        return pref.getPrefBoolean(key, true)
    }

    // ═══════════════════════════════════════════════════════════
    //  Secure Messaging: Inline Encrypt / Decrypt
    // ═══════════════════════════════════════════════════════════

    private fun openSecureSessionPanel() {
        hideMainKeyboard()
        binding?.apply {
            keyboardSecureMessaging.visible()
            keyboardSecureMessaging.setInputConnection(currentInputConnection)
            keyboardSecureMessaging.binding.etUsername.showKeyboardExt()
            keyboardSecureMessaging.binding.etUsername.requestFocus()
        }
    }

    private fun handleEncryptAction() {
        try {
            val loggedIn = secureRepo.isLoggedIn()
            if (!loggedIn) {
                openSecureSessionPanel()
                Toast.makeText(this, R.string.secure_login_required, Toast.LENGTH_SHORT).show()
                return
            }
        } catch (e: Exception) {
            openSecureSessionPanel()
            Toast.makeText(this, R.string.secure_login_required, Toast.LENGTH_SHORT).show()
            return
        }

        val prefs = getSharedPreferences(SECURE_SESSION_PREFS, Context.MODE_PRIVATE)
        val sessionId = prefs.getString(KEY_SESSION_ID, null)
        val recipientName = prefs.getString(KEY_RECIPIENT_NAME, null)

        if (sessionId.isNullOrEmpty() || recipientName.isNullOrEmpty()) {
            openSecureSessionPanel()
            Toast.makeText(this, R.string.secure_no_session, Toast.LENGTH_SHORT).show()
            return
        }

        val ic = currentInputConnection
        if (ic == null) {
            Toast.makeText(this, R.string.secure_no_text_field, Toast.LENGTH_SHORT).show()
            return
        }

        val extracted = ic.getExtractedText(ExtractedTextRequest(), 0)
        val plaintext = extracted?.text?.toString()?.trim() ?: ""

        if (plaintext.isEmpty()) {
            Toast.makeText(this, R.string.secure_type_message_hint, Toast.LENGTH_SHORT).show()
            return
        }

        Toast.makeText(this, R.string.secure_encrypting, Toast.LENGTH_SHORT).show()

        GlobalScope.launch(Dispatchers.IO) {
            val result = secureRepo.sendMessage(sessionId, recipientName, plaintext)
            withContext(Dispatchers.Main) {
                result.onSuccess { sendResult ->
                    currentInputConnection?.apply {
                        performContextMenuAction(android.R.id.selectAll)
                        commitText(sendResult.obfuscatedText, 1)
                    }
                    Toast.makeText(
                        this@KeyboardIME,
                        R.string.secure_encrypted_done,
                        Toast.LENGTH_SHORT
                    ).show()
                }.onFailure { e ->
                    Toast.makeText(
                        this@KeyboardIME,
                        "Encrypt failed: ${e.message?.take(80)}",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun handleDecryptAction() {
        try {
            val loggedIn = secureRepo.isLoggedIn()
            if (!loggedIn) {
                openSecureSessionPanel()
                Toast.makeText(this, R.string.secure_login_required, Toast.LENGTH_SHORT).show()
                return
            }
        } catch (e: Exception) {
            openSecureSessionPanel()
            Toast.makeText(this, R.string.secure_login_required, Toast.LENGTH_SHORT).show()
            return
        }

        val prefs = getSharedPreferences(SECURE_SESSION_PREFS, Context.MODE_PRIVATE)
        val recipientName = prefs.getString(KEY_RECIPIENT_NAME, null)
        val decryptFromClipboard = prefs.getBoolean(KEY_DECRYPT_FROM_CLIPBOARD, false)

        if (recipientName.isNullOrEmpty()) {
            openSecureSessionPanel()
            Toast.makeText(this, R.string.secure_no_session, Toast.LENGTH_SHORT).show()
            return
        }

        if (decryptFromClipboard) {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clipText = clipboard.primaryClip?.getItemAt(0)?.text?.toString()?.trim()

            if (clipText.isNullOrEmpty()) {
                Toast.makeText(this, R.string.secure_clipboard_empty, Toast.LENGTH_SHORT).show()
                return
            }

            performDecryption(clipText, recipientName)
            return
        }

        // Try accessibility capture mode if the service is enabled
        if (DecryptCaptureState.isServiceEnabled(this) && DecryptCaptureState.serviceInstance != null) {
            Toast.makeText(this, R.string.decrypt_capture_waiting, Toast.LENGTH_SHORT).show()
            DecryptCaptureState.startCapture(recipientName) { capturedText ->
                performDecryption(capturedText, recipientName)
            }
            return
        }

        // Fallback: clipboard-based decrypt
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clipText = clipboard.primaryClip?.getItemAt(0)?.text?.toString()?.trim()

        if (clipText.isNullOrEmpty()) {
            // No service and no clipboard — prompt to enable service
            Toast.makeText(this, R.string.decrypt_capture_enable_service, Toast.LENGTH_LONG).show()
            return
        }

        performDecryption(clipText, recipientName)
    }

    private fun performDecryption(ciphertext: String, recipientName: String) {
        Log.d("KeyboardIME", "performDecryption: text length=${ciphertext.length}, first100=${ciphertext.take(100)}")
        Toast.makeText(this, "Decrypting ${ciphertext.length} chars...", Toast.LENGTH_SHORT).show()

        GlobalScope.launch(Dispatchers.IO) {
            val result = secureRepo.decryptMessage(ciphertext, recipientName)
            withContext(Dispatchers.Main) {
                result.onSuccess { plaintext ->
                    val intent = android.content.Intent(
                        this@KeyboardIME,
                        com.frogobox.appkeyboard.ui.secure.DecryptResultActivity::class.java
                    ).apply {
                        putExtra(com.frogobox.appkeyboard.ui.secure.DecryptResultActivity.EXTRA_SENDER, recipientName)
                        putExtra(com.frogobox.appkeyboard.ui.secure.DecryptResultActivity.EXTRA_PLAINTEXT, plaintext)
                        addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    startActivity(intent)
                }.onFailure { e ->
                    Log.e("KeyboardIME", "Decrypt failed: input length=${ciphertext.length}, error=${e.message}")
                    val intent = android.content.Intent(
                        this@KeyboardIME,
                        com.frogobox.appkeyboard.ui.secure.DecryptResultActivity::class.java
                    ).apply {
                        putExtra(com.frogobox.appkeyboard.ui.secure.DecryptResultActivity.EXTRA_ERROR,
                            "Decrypt failed (${ciphertext.length} chars): ${e.message?.take(80)}")
                        addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    startActivity(intent)
                }
            }
        }
    }

}
