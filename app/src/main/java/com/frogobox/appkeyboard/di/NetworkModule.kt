package com.frogobox.appkeyboard.di

import android.content.Context
import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.local.SecureKeyStore
import com.frogobox.appkeyboard.data.remote.AuthInterceptor
import com.frogobox.appkeyboard.data.remote.SecureApiService
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
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    /**
     * Base URL for the Secure-Application FastAPI server.
     * - Emulator: 10.0.2.2 maps to host machine's localhost
     * - Physical device: replace with your machine's LAN IP
     */
    private const val BASE_URL = "http://10.0.2.2:8000/"

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
            .baseUrl(BASE_URL)
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
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit =
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

    @Provides
    @Singleton
    fun provideSecureApiService(retrofit: Retrofit): SecureApiService =
        retrofit.create(SecureApiService::class.java)

    @Provides
    @Singleton
    fun provideSecureKeyStore(
        @ApplicationContext context: Context
    ): SecureKeyStore = SecureKeyStore(context)
}