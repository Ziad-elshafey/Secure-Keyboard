package com.frogobox.appkeyboard.data.remote.dto

import com.google.gson.annotations.SerializedName

// ════════════════════════════════════════════════════════════════
//  Auth DTOs
// ════════════════════════════════════════════════════════════════

data class RegisterRequest(
    @SerializedName("username") val username: String,
    @SerializedName("email") val email: String,
    @SerializedName("password") val password: String,
    @SerializedName("display_name") val displayName: String? = null
)

data class LoginRequest(
    @SerializedName("username") val username: String,
    @SerializedName("password") val password: String
)

data class RefreshTokenRequest(
    @SerializedName("refresh_token") val refreshToken: String
)

/** Returned by /register — includes user info + tokens. */
data class RegisterResponse(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("email") val email: String,
    @SerializedName("display_name") val displayName: String?,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("is_active") val isActive: Boolean,
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("refresh_token") val refreshToken: String,
    @SerializedName("token_type") val tokenType: String = "bearer"
)

/** Returned by /login and /refresh — tokens only. */
data class TokenResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("refresh_token") val refreshToken: String,
    @SerializedName("token_type") val tokenType: String = "bearer",
    @SerializedName("expires_in") val expiresIn: Int = 86400
)

// ════════════════════════════════════════════════════════════════
//  User DTOs
// ════════════════════════════════════════════════════════════════

data class UserProfileResponse(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("email") val email: String,
    @SerializedName("display_name") val displayName: String?,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("last_seen_at") val lastSeenAt: String?,
    @SerializedName("is_active") val isActive: Boolean
)

data class UserSearchResult(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("display_name") val displayName: String?,
    @SerializedName("is_active") val isActive: Boolean
)

// ════════════════════════════════════════════════════════════════
//  E2EE Key DTOs
// ════════════════════════════════════════════════════════════════

data class UploadKeysRequest(
    @SerializedName("identity_key_public") val identityKeyPublic: String,
    @SerializedName("signed_prekey_public") val signedPrekeyPublic: String,
    @SerializedName("signed_prekey_signature") val signedPrekeySignature: String,
    @SerializedName("signed_prekey_id") val signedPrekeyId: Int
)

data class PreKeyBundleResponse(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("identity_key_public") val identityKeyPublic: String,
    @SerializedName("signed_prekey_public") val signedPrekeyPublic: String,
    @SerializedName("signed_prekey_signature") val signedPrekeySignature: String,
    @SerializedName("signed_prekey_id") val signedPrekeyId: Int
)

data class KeyStatusResponse(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("has_identity_key") val hasIdentityKey: Boolean,
    @SerializedName("has_signed_prekey") val hasSignedPrekey: Boolean,
    @SerializedName("signed_prekey_id") val signedPrekeyId: Int?,
    @SerializedName("keys_uploaded_at") val keysUploadedAt: String?
)

// ════════════════════════════════════════════════════════════════
//  Conversation DTOs
// ════════════════════════════════════════════════════════════════

data class CreateConversationRequest(
    @SerializedName("participant_ids") val participantIds: List<String>,
    @SerializedName("title") val title: String? = null
)

data class ConversationParticipant(
    @SerializedName("user_id") val userId: String,
    @SerializedName("username") val username: String,
    @SerializedName("display_name") val displayName: String?
)

data class ConversationResponse(
    @SerializedName("conversation_id") val conversationId: String,
    @SerializedName("title") val title: String?,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("last_message_at") val lastMessageAt: String?,
    @SerializedName("participants") val participants: List<ConversationParticipant>
)

// ════════════════════════════════════════════════════════════════
//  Message DTOs
// ════════════════════════════════════════════════════════════════

data class SendMessageRequest(
    @SerializedName("conversation_id") val conversationId: String,
    @SerializedName("ciphertext") val ciphertext: String,
    @SerializedName("nonce") val nonce: String,
    @SerializedName("ephemeral_public_key") val ephemeralPublicKey: String? = null
)

data class MessageResponse(
    @SerializedName("message_id") val messageId: String,
    @SerializedName("conversation_id") val conversationId: String,
    @SerializedName("sender_id") val senderId: String,
    @SerializedName("sender_username") val senderUsername: String,
    @SerializedName("obfuscated_text") val obfuscatedText: String,
    @SerializedName("obfuscation_data") val obfuscationData: Map<String, Any>?,
    @SerializedName("obfuscation_version") val obfuscationVersion: String,
    @SerializedName("seed_id") val seedId: String,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("delivered_at") val deliveredAt: String?,
    @SerializedName("status") val status: String
)

data class RevealMessageResponse(
    @SerializedName("message_id") val messageId: String,
    @SerializedName("conversation_id") val conversationId: String,
    @SerializedName("sender_id") val senderId: String,
    @SerializedName("ciphertext") val ciphertext: String,
    @SerializedName("nonce") val nonce: String,
    @SerializedName("ephemeral_public_key") val ephemeralPublicKey: String?,
    @SerializedName("obfuscation_metadata") val obfuscationMetadata: Map<String, Any>?
)
