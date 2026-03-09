package com.frogobox.appkeyboard.di

import android.content.Context
import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.local.SecureKeyStore
import com.frogobox.appkeyboard.data.remote.AuthInterceptor
import com.frogobox.appkeyboard.data.remote.SecureApiService
import com.frogobox.appkeyboard.data.remote.StegoDecodeApiService
import com.frogobox.appkeyboard.data.remote.StegoEncodeApiService
import com.frogobox.appkeyboard.data.remote.TokenRefreshAuthenticator
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Named
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    /**
     * Base URL for the Secure-Application FastAPI server.
     * - Emulator: 10.0.2.2 maps to host machine's localhost
     * - Physical device: replace with your machine's LAN IP
     */
    private const val SECURE_API_BASE_URL = "http://10.0.2.2:8000/"
    private const val STEGO_ENCODE_BASE_URL = "https://modalcd--encode.modal.run/"
    private const val STEGO_DECODE_BASE_URL = "https://modalcd--decode.modal.run/"

    @Provides
    @Singleton
    fun provideAuthTokenManager(
        @ApplicationContext context: Context
    ): AuthTokenManager = AuthTokenManager(context)

    @Provides
    @Singleton
    fun provideAuthInterceptor(
        tokenManager: AuthTokenManager
    ): AuthInterceptor = AuthInterceptor(tokenManager)

    @Provides
    @Singleton
    fun provideOkHttpClient(
        authInterceptor: AuthInterceptor,
        tokenManager: AuthTokenManager
    ): OkHttpClient {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.HEADERS
        }

        // Minimal OkHttp client for refresh calls only (no auth interceptor → no loop)
        val refreshClient = OkHttpClient.Builder()
            .addInterceptor(logging)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        val refreshRetrofit = Retrofit.Builder()
            .baseUrl(SECURE_API_BASE_URL)
            .client(refreshClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        val authenticator = TokenRefreshAuthenticator(tokenManager) {
            refreshRetrofit.create(SecureApiService::class.java)
        }

        return OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(logging)
            .authenticator(authenticator)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    @Provides
    @Singleton
    fun provideSecureApiService(okHttpClient: OkHttpClient): SecureApiService =
        Retrofit.Builder()
            .baseUrl(SECURE_API_BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SecureApiService::class.java)

    /**
     * No-auth HTTP client for Modal stego endpoints.
     * Keeps auth tokens scoped to Secure API only.
     */
    @Provides
    @Singleton
    @Named("stegoClient")
    fun provideStegoOkHttpClient(): OkHttpClient {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.HEADERS
        }

        return OkHttpClient.Builder()
            .addInterceptor(logging)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.MINUTES)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    @Provides
    @Singleton
    fun provideStegoEncodeApiService(
        @Named("stegoClient") stegoClient: OkHttpClient
    ): StegoEncodeApiService =
        Retrofit.Builder()
            .baseUrl(STEGO_ENCODE_BASE_URL)
            .client(stegoClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(StegoEncodeApiService::class.java)

    @Provides
    @Singleton
    fun provideStegoDecodeApiService(
        @Named("stegoClient") stegoClient: OkHttpClient
    ): StegoDecodeApiService =
        Retrofit.Builder()
            .baseUrl(STEGO_DECODE_BASE_URL)
            .client(stegoClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(StegoDecodeApiService::class.java)

    @Provides
    @Singleton
    fun provideSecureKeyStore(
        @ApplicationContext context: Context
    ): SecureKeyStore = SecureKeyStore(context)
}
