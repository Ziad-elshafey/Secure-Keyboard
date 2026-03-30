package com.frogobox.appkeyboard.di

import android.content.Context
import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.local.SecureKeyStore
import com.frogobox.appkeyboard.data.remote.AuthInterceptor
import com.frogobox.appkeyboard.data.remote.SecureApiService
import com.frogobox.appkeyboard.data.remote.StegoDecodeApiService
import com.frogobox.appkeyboard.data.remote.StegoEncodeApiService
import com.frogobox.appkeyboard.data.remote.TokenRefreshAuthenticator
import com.frogobox.appkeyboard.BuildConfig
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
            level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.HEADERS
                    else HttpLoggingInterceptor.Level.NONE
        }

        val refreshClient = OkHttpClient.Builder()
            .addInterceptor(logging)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        val refreshRetrofit = Retrofit.Builder()
            .baseUrl(BuildConfig.SECURE_API_URL)
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
            .baseUrl(BuildConfig.SECURE_API_URL)
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
            level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.HEADERS
                    else HttpLoggingInterceptor.Level.NONE
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
