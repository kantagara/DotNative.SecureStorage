package com.dotnative.plugins

import android.app.Activity
import android.content.Context
import android.util.AtomicFile
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.byteArrayPreferencesKey
import androidx.datastore.preferences.core.edit
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.PredefinedAeadParameters
import com.google.crypto.tink.integration.android.AndroidKeystore
import java.io.File
import java.security.GeneralSecurityException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class SecureStoragePlugin(activity: Activity) {
    private val context = activity.applicationContext

    init {
        val channel = NativeChannels.channel("dotnative.secure-storage")
        for (method in listOf("read", "write", "delete", "readAll", "deleteAll")) {
            channel.handle(method) { arguments, reply ->
                val fields = arguments as? Map<*, *>
                val namespace = fields?.get("applicationId") as? String
                val key = fields?.get("key") as? String
                val value = fields?.get("value") as? String
                if (
                    namespace == null ||
                        !namespace.matches(Regex("[A-Za-z0-9_.-]{1,128}")) ||
                        namespace == "." ||
                        namespace == ".." ||
                        (method in listOf("read", "write", "delete") &&
                            (key.isNullOrBlank() || key.length > 1024 || key.contains('\u0000'))) ||
                        (method == "write" && (value == null || value.length > 4 * 1024 * 1024))
                ) {
                    reply.failure("invalid_argument", "Invalid secure-storage arguments")
                    return@handle
                }
                val job = scope.launch {
                    try {
                        val store = storage(context, namespace)
                        val result =
                            when (method) {
                                "read" -> store.read()[key]
                                "readAll" -> store.read()
                                "write" -> {
                                    store.change { it[key!!] = value!! }
                                    null
                                }
                                "delete" -> {
                                    store.change { it.remove(key!!) }
                                    null
                                }
                                else -> {
                                    store.change { it.clear() }
                                    null
                                }
                            }
                        withContext(Dispatchers.Main) { reply.success(result) }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        withContext(Dispatchers.Main) {
                            reply.failure(
                                "secure_storage_unavailable",
                                "The protected credential store is unavailable. No plaintext fallback was used.",
                            )
                        }
                    }
                }
                reply.onCancel = { job.cancel() }
            }
        }
    }

    private class Storage(val data: DataStore<Preferences>, val aead: Aead, namespace: String) {
        private val associatedData =
            "dotnative.secure-storage/v1/$namespace".toByteArray(Charsets.UTF_8)

        private fun decode(preferences: Preferences): MutableMap<String, String> {
            val ciphertext = preferences[payload] ?: return mutableMapOf()
            val json = JSONObject(String(aead.decrypt(ciphertext, associatedData), Charsets.UTF_8))
            val result = mutableMapOf<String, String>()
            for (key in json.keys()) {
                val value = json.get(key)
                require(value is String) { "Invalid secure-storage value" }
                result[key] = value
            }
            return result
        }

        suspend fun read(): Map<String, String> = decode(data.data.first())

        suspend fun change(update: (MutableMap<String, String>) -> Unit) {
            data.edit { preferences ->
                val values = decode(preferences)
                update(values)
                preferences[payload] =
                    aead.encrypt(
                        JSONObject(values as Map<*, *>).toString().toByteArray(Charsets.UTF_8),
                        associatedData,
                    )
            }
        }
    }

    companion object {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val payload = byteArrayPreferencesKey("payload")
        private val stores = mutableMapOf<String, Storage>()

        @Synchronized
        private fun storage(context: Context, namespace: String): Storage =
            stores.getOrPut(namespace) {
                AeadConfig.register()
                val directory = File(context.noBackupFilesDir, "dotnative-secure-storage")
                check(directory.isDirectory || directory.mkdirs()) {
                    "Cannot create secure-storage directory"
                }
                val dataFile = File(directory, "$namespace.preferences_pb")
                val keyset = AtomicFile(File(directory, "$namespace.keyset"))
                val alias = "dotnative.secure-storage.$namespace"
                val existingKeyset =
                    keyset.baseFile.exists() || File(directory, "$namespace.keyset.bak").exists()
                if (!existingKeyset && dataFile.exists())
                    throw GeneralSecurityException("Encrypted storage exists without its keyset")
                if (!AndroidKeystore.hasKey(alias)) {
                    if (existingKeyset)
                        throw GeneralSecurityException("The Keystore wrapping key is missing")
                    AndroidKeystore.generateNewAes256GcmKey(alias)
                }
                val master = AndroidKeystore.getAead(alias)
                val keysetContext =
                    "dotnative.secure-storage/keyset/v1/$namespace".toByteArray(Charsets.UTF_8)
                val handle =
                    if (existingKeyset) {
                        keyset.openRead().use {
                            TinkProtoKeysetFormat.parseEncryptedKeyset(
                                it.readBytes(),
                                master,
                                keysetContext,
                                RegistryConfiguration.get(),
                            )
                        }
                    } else {
                        val created = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM)
                        val output = keyset.startWrite()
                        try {
                            output.write(
                                TinkProtoKeysetFormat.serializeEncryptedKeyset(
                                    created,
                                    master,
                                    keysetContext,
                                    RegistryConfiguration.get(),
                                ),
                            )
                            keyset.finishWrite(output)
                        } catch (error: Exception) {
                            keyset.failWrite(output)
                            throw error
                        }
                        created
                    }
                Storage(
                    PreferenceDataStoreFactory.create(scope = scope, produceFile = { dataFile }),
                    handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java),
                    namespace,
                )
            }
    }
}
