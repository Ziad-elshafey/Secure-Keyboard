package com.frogobox.appkeyboard.di

import com.frogobox.appkeyboard.data.repository.SecureMessagingRepository
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

/**
 * Hilt entry point for injecting dependencies into custom Views.
 * Custom Views (BaseKeyboard subclasses) can't use @Inject directly,
 * so we use EntryPointAccessors.fromApplication() to access this.
 */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface SecureKeyboardEntryPoint {
    fun secureMessagingRepository(): SecureMessagingRepository
}
