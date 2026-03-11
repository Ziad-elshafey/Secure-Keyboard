package com.frogobox.appkeyboard.services

import android.accessibilityservice.AccessibilityService
import android.annotation.SuppressLint
import android.graphics.PixelFormat
import android.graphics.Rect
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.frogobox.appkeyboard.R
import com.frogobox.appkeyboard.core.DecryptCaptureState

class DecryptAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "DecryptA11y"
        private const val MIN_MESSAGE_LENGTH = 5
        private const val MIN_CONTENT_DESC_LENGTH = 10
        private const val MIN_PICKER_CANDIDATE_LENGTH = 20
        private const val MAX_BUBBLE_CLIMB_DEPTH = 8
        private const val MAX_CHILD_SCAN_DEPTH = 6
        private const val MAX_SCREEN_SCAN_DEPTH = 15
        private const val PICKER_PREVIEW_MAX_CHARS = 120
        private const val SCREEN_AREA_RATIO_LIMIT = 0.5
    }

    private val TIMESTAMP_REGEX = Regex("""^\d{1,2}:\d{2}(\s?[APap][Mm])?$""")
    private val DATE_REGEX = Regex("""^\d{1,2}[/\-.]\d{1,2}([/\-.]\d{2,4})?$""")
    private val UI_CHROME_PATTERNS = listOf(
        "online", "offline", "typing", "last seen",
        "read", "delivered", "sent", "today", "yesterday",
        "unread message", "voice message", "video call",
        "missed call", "end-to-end encrypted", "tap for more",
        "forwarded", "starred", "pinned"
    )
    private val LIST_CONTAINER_CLASSES = listOf(
        "RecyclerView", "ListView", "AbsListView", "ScrollView"
    )

    private data class MessageRegion(val bounds: Rect, val text: String)

    private var touchOverlay: View? = null
    private var bannerView: View? = null
    private var pickerView: View? = null
    private var snapshotRegions: List<MessageRegion> = emptyList()
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onServiceConnected() {
        super.onServiceConnected()
        DecryptCaptureState.serviceInstance = this
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}

    override fun onInterrupt() {
        DecryptCaptureState.stopCapture()
    }

    override fun onDestroy() {
        removeAllOverlays()
        if (DecryptCaptureState.serviceInstance === this) {
            DecryptCaptureState.serviceInstance = null
        }
        super.onDestroy()
    }

    // ── UI chrome filter ─────────────────────────────────────────────

    private fun isLikelyUIChrome(text: String): Boolean {
        val trimmed = text.trim()
        if (trimmed.length < 3) return true
        if (TIMESTAMP_REGEX.matches(trimmed)) return true
        if (DATE_REGEX.matches(trimmed)) return true
        val lower = trimmed.lowercase()
        return UI_CHROME_PATTERNS.any { pattern ->
            lower == pattern || lower.startsWith("$pattern ") || lower.startsWith("$pattern,")
        }
    }

    // ── Tap-to-capture: transparent overlay captures touch coords ────

    @SuppressLint("ClickableViewAccessibility")
    fun showTapCaptureOverlay() {
        snapshotRegions = snapshotMessageRegions().also {
            Log.d(TAG, "Pre-snapshot captured ${it.size} message regions")
        }
        removeTouchOverlay()
        showBanner()

        val wm = getSystemService(WINDOW_SERVICE) as WindowManager

        val view = View(this).apply {
            setBackgroundColor(0x01000000)
            setOnTouchListener { _, event ->
                if (event.action == MotionEvent.ACTION_UP) {
                    val x = event.rawX.toInt()
                    val y = event.rawY.toInt()
                    removeTouchOverlay()
                    removeBanner()
                    findAndDeliverTextAtCoords(x, y)
                }
                true
            }
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_FULLSCREEN or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        )

        wm.addView(view, params)
        touchOverlay = view
    }

    private fun removeTouchOverlay() {
        touchOverlay?.let {
            try { (getSystemService(WINDOW_SERVICE) as WindowManager).removeView(it) }
            catch (_: Exception) {}
            touchOverlay = null
        }
    }

    // ── Core detection: snapshot first, live fallback ────────────────

    private fun findAndDeliverTextAtCoords(x: Int, y: Int) {
        // Strategy 1: pre-snapshot lookup — no live tree access needed
        val hit = snapshotRegions
            .filter { it.bounds.contains(x, y) }
            .minByOrNull { it.bounds.width().toLong() * it.bounds.height() }

        if (hit != null && hit.text.length >= MIN_MESSAGE_LENGTH) {
            Log.d(TAG, "Snapshot hit: ${hit.text.length} chars at ${hit.bounds}")
            DecryptCaptureState.deliverText(hit.text)
            return
        }

        // Strategy 2: live fallback if snapshot had no suitable region
        val root = rootInActiveWindow
        if (root == null) {
            Toast.makeText(this, R.string.decrypt_scan_failed, Toast.LENGTH_SHORT).show()
            DecryptCaptureState.stopCapture()
            return
        }

        try {
            val deepest = findNodeAtCoords(root, x, y)
            Log.d(
                TAG,
                "Live fallback tap at ($x, $y), deepest node: ${deepest?.className} text=${deepest?.text?.toString()?.take(50)}"
            )

            val bubbleText = findMessageBubbleText(deepest, root)
            if (bubbleText != null && bubbleText.length >= MIN_MESSAGE_LENGTH) {
                Log.d(TAG, "Live fallback bubble: captured ${bubbleText.length} chars: ${bubbleText.take(100)}")
                DecryptCaptureState.deliverText(bubbleText)
                return
            }

            val extracted = extractTextFromNode(deepest)
            if (extracted != null && extracted.length >= MIN_MESSAGE_LENGTH) {
                Log.d(TAG, "Live fallback extract: captured ${extracted.length} chars: ${extracted.take(100)}")
                DecryptCaptureState.deliverText(extracted)
                return
            }

            Log.d(TAG, "Live fallback failed, showing picker")
            Toast.makeText(this, R.string.decrypt_tap_fallback, Toast.LENGTH_SHORT).show()
            scanAndPickMessage()
        } finally {
            safeRecycle(root)
        }
    }

    /** Find the deepest/smallest node whose bounds contain (x, y). */
    private fun findNodeAtCoords(node: AccessibilityNodeInfo, x: Int, y: Int): AccessibilityNodeInfo? {
        val bounds = Rect()
        node.getBoundsInScreen(bounds)
        if (!bounds.contains(x, y)) return null

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val found = findNodeAtCoords(child, x, y)
            if (found != null) return found
        }

        return node
    }

    // ── Strategy 1: Walk up from tapped node to find message bubble ──

    private fun findMessageBubbleText(
        node: AccessibilityNodeInfo?,
        root: AccessibilityNodeInfo
    ): String? {
        if (node == null) return null
        val screenBounds = Rect().also { root.getBoundsInScreen(it) }
        val screenArea = screenBounds.width().toLong() * screenBounds.height()

        var current: AccessibilityNodeInfo? = node
        var depth = 0
        val candidates = mutableListOf<ScoredCandidate>()

        while (current != null && depth < MAX_BUBBLE_CLIMB_DEPTH) {
            val bounds = Rect().also { current!!.getBoundsInScreen(it) }
            val nodeArea = bounds.width().toLong() * bounds.height()

            if (nodeArea > screenArea * SCREEN_AREA_RATIO_LIMIT) break

            val className = current!!.className?.toString() ?: ""
            if (LIST_CONTAINER_CLASSES.any { className.contains(it) }) break

            current!!.contentDescription?.toString()?.trim()
                ?.takeIf { it.length >= MIN_CONTENT_DESC_LENGTH && !isLikelyUIChrome(it) }
                ?.let { candidates.add(ScoredCandidate(it, priority = 3, source = "contentDesc@depth$depth")) }

            current!!.text?.toString()?.trim()
                ?.takeIf { it.length >= MIN_MESSAGE_LENGTH && !isLikelyUIChrome(it) }
                ?.let { candidates.add(ScoredCandidate(it, priority = 2, source = "text@depth$depth")) }

            // Search entire subtree of this node (not just direct children)
            collectScoredTexts(current!!, candidates, 0, MAX_CHILD_SCAN_DEPTH, depth)

            current = current!!.parent
            depth++
        }

        if (candidates.isNotEmpty()) {
            Log.d(TAG, "Bubble candidates: ${candidates.map { "(${it.source},p=${it.priority},len=${it.text.length})" }}")
        }

        return candidates
            .sortedWith(compareByDescending<ScoredCandidate> { it.priority }.thenByDescending { it.text.length })
            .firstOrNull()?.text
    }

    /** Recursively collect scored candidates from a subtree. */
    private fun collectScoredTexts(
        node: AccessibilityNodeInfo,
        out: MutableList<ScoredCandidate>,
        childDepth: Int,
        maxChildDepth: Int,
        parentDepth: Int
    ) {
        if (childDepth > maxChildDepth) return
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            child.contentDescription?.toString()?.trim()
                ?.takeIf { it.length >= MIN_CONTENT_DESC_LENGTH && !isLikelyUIChrome(it) }
                ?.let { out.add(ScoredCandidate(it, priority = 2, source = "subtreeDesc@p$parentDepth.c$childDepth")) }
            child.text?.toString()?.trim()
                ?.takeIf { it.length >= MIN_MESSAGE_LENGTH && !isLikelyUIChrome(it) }
                ?.let { out.add(ScoredCandidate(it, priority = 1, source = "subtreeText@p$parentDepth.c$childDepth")) }
            collectScoredTexts(child, out, childDepth + 1, maxChildDepth, parentDepth)
        }
    }

    private data class ScoredCandidate(val text: String, val priority: Int, val source: String)

    // ── Strategy 2: Original extraction (improved with filtering) ────

    private fun getNodeText(node: AccessibilityNodeInfo): String? {
        val text = node.text?.toString()?.trim()?.takeIf { it.isNotEmpty() && !isLikelyUIChrome(it) }
        val desc = node.contentDescription?.toString()?.trim()?.takeIf { it.isNotEmpty() && !isLikelyUIChrome(it) }
        return when {
            text != null && desc != null -> if (desc.length > text.length) desc else text
            text != null -> text
            desc != null -> desc
            else -> null
        }
    }

    private fun extractTextFromNode(node: AccessibilityNodeInfo?): String? {
        if (node == null) return null

        val candidates = mutableListOf<String>()

        getNodeText(node)?.let { candidates.add(it) }

        collectAllTexts(node, candidates, 0, MAX_CHILD_SCAN_DEPTH)

        var parent = node.parent
        var depth = 0
        while (parent != null && depth < 4) {
            val className = parent.className?.toString() ?: ""
            if (LIST_CONTAINER_CLASSES.any { className.contains(it) }) break

            getNodeText(parent)?.let { candidates.add(it) }
            collectAllTexts(parent, candidates, 0, 4)
            parent = parent.parent
            depth++
        }

        val best = candidates
            .filter { it.length >= MIN_MESSAGE_LENGTH && !isLikelyUIChrome(it) }
            .maxByOrNull { it.length }
        if (best != null && candidates.size > 1) {
            Log.d(TAG, "Extract candidates: ${candidates.size}, lengths: ${candidates.map { it.length }.sorted()}")
        }
        return best
    }

    private fun collectAllTexts(
        node: AccessibilityNodeInfo,
        out: MutableList<String>,
        depth: Int,
        maxDepth: Int
    ) {
        if (depth > maxDepth) return
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            getNodeText(child)?.let { out.add(it) }
            collectAllTexts(child, out, depth + 1, maxDepth)
        }
    }

    // ── Snapshot of visible message regions ───────────────────────────

    private fun snapshotMessageRegions(): List<MessageRegion> {
        val root = rootInActiveWindow ?: return emptyList()
        val regions = mutableListOf<MessageRegion>()
        try {
            collectMessageRegions(root, regions, 0)
        } finally {
            safeRecycle(root)
        }
        return regions
    }

    private fun collectMessageRegions(
        node: AccessibilityNodeInfo,
        out: MutableList<MessageRegion>,
        depth: Int
    ) {
        if (depth > MAX_SCREEN_SCAN_DEPTH) return
        val bounds = Rect()
        node.getBoundsInScreen(bounds)
        if (bounds.width() <= 0 || bounds.height() <= 0) return

        node.contentDescription?.toString()?.trim()?.let { raw ->
            val cleaned = stripContentDescriptionPrefix(raw)
            if (cleaned.length >= MIN_MESSAGE_LENGTH && !isLikelyUIChrome(cleaned)) {
                out.add(MessageRegion(Rect(bounds), cleaned))
            }
        }

        node.text?.toString()?.trim()?.let { txt ->
            if (txt.length >= MIN_MESSAGE_LENGTH && !isLikelyUIChrome(txt)) {
                out.add(MessageRegion(Rect(bounds), txt))
            }
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectMessageRegions(child, out, depth + 1)
        }
    }

    private val CONTENT_DESC_PREFIX = Regex(
        """^[^,]{1,40},\s*\d{1,2}:\d{2}(\s?[APap][Mm])?,\s*"""
    )

    private fun stripContentDescriptionPrefix(raw: String): String {
        val stripped = CONTENT_DESC_PREFIX.replaceFirst(raw, "")
        return if (stripped.isEmpty() || stripped.length == raw.length) raw else stripped
    }

    // ── Banner (instruction bar at top) ──────────────────────────────

    private fun showBanner() {
        removeBanner()

        val wm = getSystemService(WINDOW_SERVICE) as WindowManager
        val view = LayoutInflater.from(this).inflate(R.layout.overlay_decrypt_capture, null)

        view.findViewById<Button>(R.id.btnCancelCapture).setOnClickListener {
            DecryptCaptureState.stopCapture()
            Toast.makeText(this, R.string.decrypt_capture_cancelled, Toast.LENGTH_SHORT).show()
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.TOP }

        wm.addView(view, params)
        bannerView = view
    }

    private fun removeBanner() {
        bannerView?.let {
            try { (getSystemService(WINDOW_SERVICE) as WindowManager).removeView(it) }
            catch (_: Exception) {}
            bannerView = null
        }
    }

    // ── Screen scan + picker (fallback, with filtering) ──────────────

    fun scanAndPickMessage() {
        val root = rootInActiveWindow
        if (root == null) {
            Toast.makeText(this, R.string.decrypt_scan_failed, Toast.LENGTH_SHORT).show()
            DecryptCaptureState.stopCapture()
            return
        }

        try {
            val texts = mutableListOf<String>()
            collectTexts(root, texts, 0)

            val candidates = texts
                .filter { it.length >= MIN_PICKER_CANDIDATE_LENGTH && !isLikelyUIChrome(it) }
                .distinct()

            if (candidates.isEmpty()) {
                Toast.makeText(this, R.string.decrypt_no_messages_found, Toast.LENGTH_SHORT).show()
                DecryptCaptureState.stopCapture()
                return
            }

            mainHandler.post { showPickerOverlay(candidates) }
        } finally {
            safeRecycle(root)
        }
    }

    private fun collectTexts(node: AccessibilityNodeInfo, out: MutableList<String>, depth: Int) {
        if (depth > MAX_SCREEN_SCAN_DEPTH) return
        node.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { out.add(it) }
        node.contentDescription?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { out.add(it) }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectTexts(child, out, depth + 1)
        }
    }

    private fun showPickerOverlay(candidates: List<String>) {
        removePicker()

        val wm = getSystemService(WINDOW_SERVICE) as WindowManager
        val view = LayoutInflater.from(this).inflate(R.layout.overlay_message_picker, null)
        val container = view.findViewById<LinearLayout>(R.id.messageListContainer)

        for (text in candidates.reversed()) {
            val item = TextView(this).apply {
                this.text = if (text.length > PICKER_PREVIEW_MAX_CHARS) text.take(PICKER_PREVIEW_MAX_CHARS) + "\u2026" else text
                textSize = 14f
                setTextColor(0xFFFFFFFF.toInt())
                setBackgroundColor(0xFF444444.toInt())
                setPadding(24, 20, 24, 20)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = 6 }
                setOnClickListener {
                    removeAllOverlays()
                    DecryptCaptureState.deliverText(text)
                }
            }
            container.addView(item)
        }

        view.findViewById<Button>(R.id.btnCancelPicker).setOnClickListener {
            DecryptCaptureState.stopCapture()
            Toast.makeText(this, R.string.decrypt_capture_cancelled, Toast.LENGTH_SHORT).show()
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.BOTTOM }

        wm.addView(view, params)
        pickerView = view
    }

    private fun removePicker() {
        pickerView?.let {
            try { (getSystemService(WINDOW_SERVICE) as WindowManager).removeView(it) }
            catch (_: Exception) {}
            pickerView = null
        }
    }

    fun removeAllOverlays() {
        removeTouchOverlay()
        removeBanner()
        removePicker()
    }

    // ── Memory management ────────────────────────────────────────────

    @Suppress("DEPRECATION")
    private fun safeRecycle(node: AccessibilityNodeInfo?) {
        try { node?.recycle() } catch (_: Exception) {}
    }
}
