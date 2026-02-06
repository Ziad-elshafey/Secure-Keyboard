package com.frogobox.appkeyboard.data.remote

import com.frogobox.appkeyboard.data.remote.dto.*
import retrofit2.http.*

/**
 * Retrofit interface for the Secure-Application FastAPI server.
 *
 * Base URL: configured via Hilt NetworkModule (default http://10.0.2.2:8000/)
 *
 * Auth endpoints require no token.
 * All other endpoints require Authorization: Bearer <access_token> header,
 * which is injected automatically by [AuthInterceptor].
 */
interface SecureApiService {

    // ════════════════════════════════════════════════════════════
    //  Auth (no token required)
    // ════════════════════════════════════════════════════════════

    @POST("api/auth/register")
    suspend fun register(@Body request: RegisterRequest): RegisterResponse

    @POST("api/auth/login")
    suspend fun login(@Body request: LoginRequest): TokenResponse

    @POST("api/auth/refresh")
    suspend fun refreshToken(@Body request: RefreshTokenRequest): TokenResponse

    // ════════════════════════════════════════════════════════════
    //  Users (token required)
    // ════════════════════════════════════════════════════════════

    @GET("api/users/me")
    suspend fun getCurrentUser(): UserProfileResponse

    @GET("api/users/{userId}")
    suspend fun getUser(@Path("userId") userId: String): UserProfileResponse

    @GET("api/users/search/")
    suspend fun searchUsers(
        @Query("query") query: String,
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 20
    ): List<UserSearchResult>

    // ════════════════════════════════════════════════════════════
    //  E2EE Keys (token required)
    // ════════════════════════════════════════════════════════════

    @POST("api/keys/upload")
    suspend fun uploadKeys(@Body request: UploadKeysRequest): KeyStatusResponse

    @GET("api/keys/bundle/{userId}")
    suspend fun getKeyBundle(@Path("userId") userId: String): PreKeyBundleResponse

    @GET("api/keys/status")
    suspend fun getKeyStatus(): KeyStatusResponse

    // ════════════════════════════════════════════════════════════
    //  Conversations (token required)
    // ════════════════════════════════════════════════════════════

    @POST("api/conversations/")
    suspend fun createConversation(@Body request: CreateConversationRequest): ConversationResponse

    @GET("api/conversations/")
    suspend fun getConversations(
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 50
    ): List<ConversationResponse>

    @GET("api/conversations/{conversationId}")
    suspend fun getConversation(
        @Path("conversationId") conversationId: String
    ): ConversationResponse

    // ════════════════════════════════════════════════════════════
    //  Messages (token required)
    // ════════════════════════════════════════════════════════════

    @POST("api/messages/send")
    suspend fun sendMessage(@Body request: SendMessageRequest): MessageResponse

    @GET("api/messages/inbox")
    suspend fun getInbox(
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 50
    ): List<MessageResponse>

    @GET("api/messages/conversation/{conversationId}")
    suspend fun getConversationMessages(
        @Path("conversationId") conversationId: String,
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 50
    ): List<MessageResponse>

    @GET("api/messages/{messageId}/reveal")
    suspend fun revealMessage(
        @Path("messageId") messageId: String
    ): RevealMessageResponse
}
