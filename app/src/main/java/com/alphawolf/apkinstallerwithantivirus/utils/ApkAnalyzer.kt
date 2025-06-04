package com.alphawolf.apkinstallerwithantivirus.utils

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.DexFile
import java.io.File
import java.util.concurrent.ConcurrentHashMap

class ApkAnalyzer(private val context: Context) {
    data class AppInfo(
        val appName: String,
        val packageName: String,
        val permissions: List<String>,
        val description: String?
    )
    
    // Add cache for analyzed DEX files to prevent re-analysis
    private val dexAnalysisCache = ConcurrentHashMap<String, List<String>>()
    private val maxCacheSize = 50
    
    companion object {
        val SUSPICIOUS_PERMISSIONS = listOf(
            "android.permission.SEND_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.WRITE_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_PHONE_STATE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.READ_HISTORY_BOOKMARKS",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.GET_ACCOUNTS",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.WRITE_SETTINGS",
            "android.permission.READ_NOTIFICATION_POLICY",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE"
        )

        // Enhanced suspicious API detection
        private val SUSPICIOUS_APIS = listOf(
            // SMS and Telephony
            "Landroid/telephony/SmsManager;->sendTextMessage",
            "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
            "Landroid/telephony/TelephonyManager;->getLine1Number",
            
            // Location Services
            "Landroid/location/LocationManager;->requestLocationUpdates",
            "Landroid/location/LocationManager;->getLastKnownLocation",
            
            // Camera and Recording
            "Landroid/media/MediaRecorder;->start",
            "Landroid/media/AudioRecord;->startRecording",
            "Landroid/hardware/Camera;->takePicture",
            
            // Crypto and Encryption
            "Ljavax/crypto/Cipher;->doFinal",
            "Ljava/security/MessageDigest;->digest",
            
            // Network Communication
            "Ljava/net/HttpURLConnection;->connect",
            "Lokhttp3/OkHttpClient;->newCall",
            
            // File Operations
            "Ljava/io/FileOutputStream;->write",
            "Landroid/content/ContentResolver;->query",
            "Landroid/content/ContentResolver;->insert",
            "Landroid/content/ContentResolver;->delete",
            
            // System Services
            "Landroid/app/admin/DevicePolicyManager;->lockNow",
            "Landroid/app/admin/DevicePolicyManager;->wipeData",
            
            // Runtime Execution
            "Ljava/lang/Runtime;->exec",
            "Ljava/lang/ProcessBuilder;->start",
            
            // Reflection (often used for obfuscation)
            "Ljava/lang/Class;->forName",
            "Ljava/lang/reflect/Method;->invoke",
            
            // Dynamic Loading
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/PathClassLoader;-><init>"
        )

        // Suspicious class patterns
        private val SUSPICIOUS_CLASS_PATTERNS = listOf(
            "Landroid/telephony/SmsManager",
            "Landroid/telephony/TelephonyManager",
            "Landroid/location/LocationManager",
            "Landroid/media/MediaRecorder",
            "Landroid/hardware/Camera",
            "Ljavax/crypto/",
            "Landroid/content/ContentResolver",
            "Landroid/app/admin/DevicePolicyManager",
            "Ljava/lang/Runtime",
            "Ljava/lang/ProcessBuilder",
            "Ldalvik/system/DexClassLoader",
            "Ldalvik/system/PathClassLoader"
        )
    }

    /**
     * Analyze APK with proper resource management and caching
     */
    fun analyzeApk(uri: Uri): List<String> {
        val results = mutableListOf<String>()
        var tempFile: File? = null
        
        try {
            // Create temporary file to analyze
            tempFile = createTempFileFromUri(uri)
            
            // Analyze APK permissions
            results.addAll(analyzePermissions(tempFile.absolutePath))
            
            // Analyze DEX files for suspicious API usage with caching
            results.addAll(analyzeDexFiles(tempFile))
            
        } catch (e: OutOfMemoryError) {
            // Clear cache and suggest garbage collection on OOM
            clearCache()
            System.gc()
            results.add("Error: Out of memory during analysis. Try reducing batch size.")
        } catch (e: Exception) {
            results.add("Error analyzing APK: ${e.message}")
        } finally {
            // Always clean up temp file
            tempFile?.let { file ->
                try {
                    if (file.exists()) {
                        file.delete()
                    }
                } catch (e: Exception) {
                    // Ignore cleanup errors
                }
            }
        }
        
        return results
    }

    /**
     * Create temporary file with proper error handling
     */
    fun createTempFileFromUri(uri: Uri): File {
        val tempFile = File.createTempFile("analysis_", ".apk", context.cacheDir)
        
        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (e: Exception) {
            // Clean up on error
            if (tempFile.exists()) {
                tempFile.delete()
            }
            throw e
        }
        
        return tempFile
    }

    /**
     * Analyze permissions with memory optimization
     */
    fun analyzePermissions(apkPath: String): List<String> {
        val results = mutableListOf<String>()
        
        try {
            val packageInfo = context.packageManager.getPackageArchiveInfo(
                apkPath,
                PackageManager.GET_PERMISSIONS
            )

            val permissions = packageInfo?.requestedPermissions ?: emptyArray()
            val suspiciousPermissions = permissions.filter { permission ->
                SUSPICIOUS_PERMISSIONS.any { it == permission }
            }

            if (suspiciousPermissions.isNotEmpty()) {
                results.add("SUSPICIOUS: Found potentially dangerous permissions:")
                suspiciousPermissions.forEach { permission ->
                    results.add("- $permission")
                }
            } else {
                results.add("No suspicious permissions found")
            }
        } catch (e: Exception) {
            results.add("Error analyzing permissions: ${e.message}")
        }

        return results
    }

    /**
     * Analyze DEX files with proper resource management and caching
     */
    fun analyzeDexFiles(apkFile: File): List<String> {
        // Check cache first
        val cacheKey = "${apkFile.absolutePath}_${apkFile.lastModified()}"
        dexAnalysisCache[cacheKey]?.let { cachedResult ->
            return cachedResult
        }
        
        // Clear cache if it's getting too large
        if (dexAnalysisCache.size > maxCacheSize) {
            dexAnalysisCache.clear()
            System.gc()
        }
        
        val results = mutableListOf<String>()
        val suspiciousApisFound = mutableSetOf<String>()
        var dexFile: DexFile? = null

        try {
            // Load DEX file - this is the correct type, not Closeable
            dexFile = DexFileFactory.loadDexFile(apkFile, Opcodes.getDefault())
            
            // Process classes in smaller batches to prevent memory issues
            val classList = dexFile.classes.toList()
            val batchSize = 100 // Process classes in smaller batches
            
            for (i in classList.indices step batchSize) {
                val endIndex = minOf(i + batchSize, classList.size)
                val batch = classList.subList(i, endIndex)
                
                try {
                    for (classDef in batch) {
                        analyzeClass(classDef, suspiciousApisFound, results)
                    }
                    
                    // Periodically suggest garbage collection during large analysis
                    if (i > 0 && i % (batchSize * 5) == 0) {
                        System.gc()
                    }
                    
                } catch (e: OutOfMemoryError) {
                    results.add("Warning: Memory limit reached during DEX analysis")
                    break
                } catch (e: Exception) {
                    results.add("Warning: Error analyzing batch $i-$endIndex: ${e.message}")
                    continue
                }
            }

            if (suspiciousApisFound.isNotEmpty()) {
                results.add("SUSPICIOUS API calls found:")
                suspiciousApisFound.forEach { api ->
                    results.add("SUSPICIOUS API: $api")
                }
            } else {
                results.add("No suspicious API usage found")
            }

        } catch (e: OutOfMemoryError) {
            results.add("Error: Out of memory analyzing DEX files")
            clearCache()
            System.gc()
        } catch (e: Exception) {
            results.add("Error analyzing DEX files: ${e.message}")
        } finally {
            // DexFile doesn't implement Closeable, so we just null the reference
            dexFile = null
            // Suggest garbage collection after analysis
            System.gc()
        }
        
        // Cache the results
        dexAnalysisCache[cacheKey] = results.toList()
        
        return results
    }

    /**
     * Analyze class with memory optimization
     */
    private fun analyzeClass(
        classDef: ClassDef, 
        suspiciousApisFound: MutableSet<String>, 
        results: MutableList<String>
    ) {
        try {
            val className = classDef.type
            
            // Check if class itself is suspicious
            if (isSuspiciousClass(className)) {
                suspiciousApisFound.add(className.substring(1, className.length - 1).replace('/', '.'))
            }
            
            // Analyze methods with memory limits
            val methods = classDef.methods.toList()
            val maxMethodsToAnalyze = 50 // Limit methods per class to prevent memory issues
            
            methods.take(maxMethodsToAnalyze).forEach { method ->
                try {
                    analyzeMethod(method, className, suspiciousApisFound)
                } catch (e: Exception) {
                    // Continue with next method on error
                }
            }
            
            if (methods.size > maxMethodsToAnalyze) {
                // Log that we're limiting analysis for memory reasons
                results.add("Note: Limited analysis for class $className (${methods.size} methods, analyzed $maxMethodsToAnalyze)")
            }
            
        } catch (e: Exception) {
            results.add("Error analyzing class ${classDef.type}: ${e.message}")
        }
    }

    /**
     * Analyze method with instruction limits
     */
    private fun analyzeMethod(
        method: Method, 
        className: String, 
        suspiciousApisFound: MutableSet<String>
    ) {
        try {
            val implementation = method.implementation ?: return
            
            // Limit the number of instructions to analyze per method
            val instructions = implementation.instructions.toList()
            val maxInstructions = 200 // Limit instructions per method
            
            instructions.take(maxInstructions).forEach { instruction ->
                val instructionString = instruction.toString()
                
                // Check for suspicious API calls
                SUSPICIOUS_APIS.forEach { suspiciousApi ->
                    if (instructionString.contains(suspiciousApi)) {
                        val apiName = extractApiName(suspiciousApi)
                        suspiciousApisFound.add(apiName)
                    }
                }
                
                // Check for dynamic loading patterns
                if (instructionString.contains("invoke-virtual") || 
                    instructionString.contains("invoke-static")) {
                    checkForDynamicLoading(instructionString, suspiciousApisFound)
                }
                
                // Check for reflection usage
                if (instructionString.contains("java/lang/Class") &&
                    instructionString.contains("forName")) {
                    suspiciousApisFound.add("java.lang.Class.forName")
                }
            }
            
        } catch (e: Exception) {
            // Continue with next method on error
        }
    }

    private fun isSuspiciousClass(className: String): Boolean {
        return SUSPICIOUS_CLASS_PATTERNS.any { pattern ->
            className.startsWith(pattern)
        }
    }

    private fun extractApiName(apiCall: String): String {
        return try {
            // Extract meaningful API name from full method signature
            val parts = apiCall.split(";->")
            if (parts.size >= 2) {
                val className = parts[0].substring(1).replace('/', '.')
                val methodName = parts[1]
                "$className.$methodName"
            } else {
                apiCall.substring(1).replace('/', '.')
            }
        } catch (e: Exception) {
            apiCall
        }
    }

    private fun checkForDynamicLoading(
        instructionString: String, 
        suspiciousApisFound: MutableSet<String>
    ) {
        when {
            instructionString.contains("DexClassLoader") -> {
                suspiciousApisFound.add("dalvik.system.DexClassLoader")
            }
            instructionString.contains("PathClassLoader") -> {
                suspiciousApisFound.add("dalvik.system.PathClassLoader")
            }
            instructionString.contains("Runtime") && instructionString.contains("exec") -> {
                suspiciousApisFound.add("java.lang.Runtime.exec")
            }
        }
    }

    /**
     * Extract app info with proper error handling
     */
    fun extractAppInfo(apkPath: String): AppInfo {
        return try {
            val packageInfo = context.packageManager.getPackageArchiveInfo(
                apkPath,
                PackageManager.GET_PERMISSIONS
            )
            
            val appName = packageInfo?.applicationInfo?.loadLabel(context.packageManager)?.toString() ?: "Unknown"
            val permissions = packageInfo?.requestedPermissions?.toList() ?: emptyList()
            val description = packageInfo?.applicationInfo?.loadDescription(context.packageManager)?.toString()
            val packageName = packageInfo?.packageName ?: "Unknown"
            
            AppInfo(appName, packageName, permissions, description)
        } catch (e: Exception) {
            AppInfo("Unknown", "Unknown", emptyList(), null)
        }
    }
    
    /**
     * Clear analysis cache to free memory
     */
    fun clearCache() {
        dexAnalysisCache.clear()
    }
    
    /**
     * Get cache statistics
     */
    fun getCacheStats(): String {
        return "DEX Analysis Cache: ${dexAnalysisCache.size}/$maxCacheSize entries"
    }
}