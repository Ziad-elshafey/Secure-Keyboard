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

    @POST("api/auth/logout")
    suspend fun logout()

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

    @GET("api/keys/bundle/by-username/{username}")
    suspend fun getKeyBundleByUsername(
        @Path("username") username: String
    ): PreKeyBundleResponse

    // ════════════════════════════════════════════════════════════
    //  Sessions (token required) — v3.0 replaces Conversations
    // ════════════════════════════════════════════════════════════

    @POST("api/sessions/")
    suspend fun createSession(@Body request: CreateSessionRequest): SessionResponse

    @GET("api/sessions/")
    suspend fun listSessions(
        @Query("active_only") activeOnly: Boolean = true
    ): List<SessionResponse>

    @GET("api/sessions/{sessionId}")
    suspend fun getSession(
        @Path("sessionId") sessionId: String
    ): SessionResponse

    @POST("api/sessions/{sessionId}/counter")
    suspend fun getNextCounter(
        @Path("sessionId") sessionId: String
    ): CounterResponse

    @DELETE("api/sessions/{sessionId}")
    suspend fun deactivateSession(
        @Path("sessionId") sessionId: String
    )

    @GET("api/sessions/{sessionId}/ephemeral-key")
    suspend fun getEphemeralKey(
        @Path("sessionId") sessionId: String
    ): EphemeralKeyResponse

    // ════════════════════════════════════════════════════════════
    //  Obfuscation (token required) — v3.0 replaces Messages
    // ════════════════════════════════════════════════════════════

    @POST("api/obfuscation/obfuscate")
    suspend fun obfuscate(@Body request: ObfuscateRequest): ObfuscateResponse

    @POST("api/obfuscation/deobfuscate")
    suspend fun deobfuscate(@Body request: DeobfuscateRequest): DeobfuscateResponse
}
