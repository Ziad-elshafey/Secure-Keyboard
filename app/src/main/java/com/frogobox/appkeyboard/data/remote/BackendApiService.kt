package com.frogobox.appkeyboard.data.remote

import com.google.gson.annotations.SerializedName
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import java.util.concurrent.TimeUnit

/**
 * Backend API Service for secure messaging demo
 * Connects to Flask mock server for blind upload/retrieval
 */
interface BackendApiService {
    
    @POST("api/upload")
    suspend fun uploadEncrypted(@Body request: UploadRequest): Response<UploadResponse>
    
    @POST("api/retrieve")
    suspend fun retrieveEncrypted(@Body request: RetrieveRequest): Response<RetrieveResponse>
    
    @GET("api/health")
    suspend fun healthCheck(): Response<HealthResponse>
    
    companion object {
        private const val BASE_URL = "http://10.0.2.2:5000/" // Android emulator localhost
        
        fun create(): BackendApiService {
            val loggingInterceptor = HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.BODY
            }
            
            val client = OkHttpClient.Builder()
                .addInterceptor(loggingInterceptor)
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .build()
            
            val retrofit = Retrofit.Builder()
                .baseUrl(BASE_URL)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
            
            return retrofit.create(BackendApiService::class.java)
        }
    }
}

// Request/Response DTOs
data class UploadRequest(
    @SerializedName("ciphertext")
    val ciphertext: String
)

data class UploadResponse(
    @SerializedName("messageId")
    val messageId: String,
    
    @SerializedName("decoyText")
    val decoyText: String,
    
    @SerializedName("timestamp")
    val timestamp: String? = null
)

data class RetrieveRequest(
    @SerializedName("decoyText")
    val decoyText: String
)

data class RetrieveResponse(
    @SerializedName("messageId")
    val messageId: String,
    
    @SerializedName("ciphertext")
    val ciphertext: String,
    
    @SerializedName("timestamp")
    val timestamp: String? = null
)

data class HealthResponse(
    @SerializedName("status")
    val status: String,
    
    @SerializedName("messages_stored")
    val messagesStored: Int
)
