package com.alphawolf.apkinstallerwithantivirus.batch

import android.content.Context
import android.net.Uri
import com.alphawolf.apkinstallerwithantivirus.BuildConfig
import com.alphawolf.apkinstallerwithantivirus.utils.ApkAnalyzer
import com.alphawolf.apkinstallerwithantivirus.utils.GeminiApiHelper
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Class to analyze multiple APK files in batch and export results to CSV
 * Fixed for memory leaks and OutOfMemory issues
 */
class BatchApkAnalyzer(
    private val context: Context,
    private val llmBatchSize: Int = 8,
    private val parallelBatchSize: Int = 2
) {

    // Progress callback interface
    interface ProgressCallback {
        fun onProgress(current: Int, total: Int, message: String)
    }

    private var progressCallback: ProgressCallback? = null
    
    // Use ConcurrentHashMap for thread safety and limit cache size
    private val analysisCache = ConcurrentHashMap<String, AnalysisResult>()
    private val maxCacheSize = 500 // Limit cache size to prevent memory issues
    
    // Coroutine scope for proper cleanup
    private val analysisScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Semaphore for controlling concurrent file operations
    private val fileOperationSemaphore = Semaphore(2)
    
    // Track temporary files for cleanup
    private val tempFiles = Collections.synchronizedSet(mutableSetOf<File>())

    fun setProgressCallback(callback: ProgressCallback?) {
        this.progressCallback = callback
    }

    // Risk levels enum for clarity
    enum class RiskLevel(val label: String) {
        SAFE("SAFE"),
        DANGEROUS("DANGEROUS"),
        UNKNOWN("UNKNOWN")
    }

    /**
     * Batch analyzes APK files with memory optimization
     */
    suspend fun analyzeDatasetAndGenerateReport(
        datasetRootPath: String,
        outputPath: String
    ): String = withContext(Dispatchers.IO) {
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val outputDir = File(outputPath).apply { mkdirs() }

        try {
            // Clear cache if it's getting too large
            if (analysisCache.size > maxCacheSize) {
                analysisCache.clear()
                System.gc()
            }

            // Scan dataset first
            val datasetEntries = scanDatasetFolder(datasetRootPath)
            if (datasetEntries.isEmpty()) {
                return@withContext "Không tìm thấy APK trong thư mục dataset."
            }

            // Process in smaller chunks to avoid memory issues
            val analysisResults = analyzeInChunks(datasetEntries)

            if (analysisResults.isEmpty()) {
                return@withContext "Không thể phân tích APK. Vui lòng kiểm tra kết nối mạng và API key Gemini."
            }

            // Create output files with proper resource management
            val datasetFile = File(outputDir, "dataset_info_$timestamp.csv")
            val resultsFile = File(outputDir, "analysis_results_$timestamp.csv")

            createDatasetCSV(datasetFile, datasetEntries)
            createResultsCSV(resultsFile, datasetEntries, analysisResults)

            // Generate Python script
            val pythonScript = generatePythonScript(
                datasetFile.absolutePath, 
                resultsFile.absolutePath, 
                outputDir.absolutePath
            )
            File(outputDir, "calculate_metrics_$timestamp.py").writeText(pythonScript)

            return@withContext "Phân tích hoàn tất!\n" +
                    "Đã phân tích: ${datasetEntries.size} APK\n" +
                    "Dataset: ${datasetFile.absolutePath}\n" +
                    "Kết quả: ${resultsFile.absolutePath}"

        } catch (e: OutOfMemoryError) {
            // Handle OOM specifically
            cleanup()
            return@withContext "Lỗi: Không đủ bộ nhớ. Hãy thử giảm batch size hoặc parallel batches."
        } catch (e: Exception) {
            return@withContext "Lỗi: ${e.message}"
        } finally {
            // Always cleanup
            cleanup()
        }
    }

    /**
     * Process dataset in smaller chunks to manage memory
     */
    private suspend fun analyzeInChunks(entries: List<DatasetEntry>): Map<String, AnalysisResult> {
        val results = ConcurrentHashMap<String, AnalysisResult>()
        val chunkSize = min(llmBatchSize * parallelBatchSize * 2, 50) // Limit chunk size
        
        for (i in entries.indices step chunkSize) {
            val chunk = entries.subList(i, min(i + chunkSize, entries.size))
            
            try {
                val chunkResults = analyzeBatch(chunk)
                results.putAll(chunkResults)
                
                // Clean up after each chunk
                cleanupTempFiles()
                System.gc()
                
                val processedCount = min(i + chunkSize, entries.size)
                val progressPercent = (processedCount * 100 / entries.size)
                progressCallback?.onProgress(
                    processedCount, 
                    entries.size, 
                    "Đã xử lý $processedCount/${entries.size} APK ($progressPercent%)"
                )
                
            } catch (e: Exception) {
                println("❌ Lỗi xử lý chunk ${i}-${min(i + chunkSize, entries.size)}: ${e.message}")
                // Continue with next chunk instead of failing completely
            }
        }
        
        return results
    }

    /**
     * Optimized batch analysis with proper resource management
     */
    private suspend fun analyzeBatch(entries: List<DatasetEntry>): Map<String, AnalysisResult> = 
        withContext(Dispatchers.IO) {
            val results = ConcurrentHashMap<String, AnalysisResult>()
            
            try {
                // Process in parallel batches with limited concurrency
                for (i in entries.indices step (llmBatchSize * parallelBatchSize)) {
                    val endIndex = min(i + (llmBatchSize * parallelBatchSize), entries.size)
                    val superBatch = entries.subList(i, endIndex)
                    
                    val parallelBatches = superBatch.chunked(llmBatchSize)
                    
                    // Use limited concurrency to prevent resource exhaustion
                    val semaphore = Semaphore(parallelBatchSize)
                    
                    val batchResults = parallelBatches.map { batch ->
                        async(Dispatchers.IO) {
                            semaphore.withPermit {
                                try {
                                    analyzeBatchWithLLM(batch)
                                } catch (e: Exception) {
                                    println("⚠️ Lỗi phân tích batch: ${e.message}")
                                    emptyMap<String, AnalysisResult>()
                                }
                            }
                        }
                    }.awaitAll()
                    
                    // Merge results
                    batchResults.forEach { batchResult ->
                        results.putAll(batchResult)
                    }
                }
                
            } catch (e: Exception) {
                println("💥 Lỗi batch analysis: ${e.message}")
            }
            
            return@withContext results
        }

    /**
     * Analyze batch with proper resource cleanup
     */
    private suspend fun analyzeBatchWithLLM(entries: List<DatasetEntry>): Map<String, AnalysisResult> = 
        withContext(Dispatchers.IO) {
            val results = mutableMapOf<String, AnalysisResult>()
            val localTempFiles = mutableListOf<File>() // Track temp files for this batch
            
            try {
                if (entries.isEmpty()) return@withContext results

                // Check cache first
                val uncachedEntries = entries.filter { entry ->
                    val cacheKey = "${entry.apkPath}_${File(entry.apkPath).lastModified()}"
                    val cached = analysisCache[cacheKey]
                    if (cached != null) {
                        results[entry.apkPath] = cached
                        false
                    } else {
                        true
                    }
                }

                if (uncachedEntries.isEmpty()) return@withContext results

                // Extract APK info with proper resource management
                val apkInfoList = uncachedEntries.mapNotNull { entry ->
                    fileOperationSemaphore.withPermit {
                        try {
                            val analyzer = ApkAnalyzer(context)
                            val tempFile = analyzer.createTempFileFromUri(Uri.fromFile(File(entry.apkPath)))
                            localTempFiles.add(tempFile) // Track for cleanup
                            tempFiles.add(tempFile) // Track globally
                            
                            val appInfo = analyzer.extractAppInfo(tempFile.absolutePath)
                            val basicAnalysis = analyzer.analyzeApk(Uri.fromFile(File(entry.apkPath)))
                            
                            // Clear analyzer cache periodically to prevent memory buildup
                            analyzer.clearCache()
                            
                            val suspiciousApis = basicAnalysis
                                .filter { it.contains("SUSPICIOUS API", ignoreCase = true) }
                                .mapNotNull { line ->
                                    val apiMatch = Regex("SUSPICIOUS API:\\s*([\\w.]+)").find(line)
                                    apiMatch?.groupValues?.get(1)
                                }
                                .distinct()
                            
                            GeminiApiHelper.ApkBatchInfo(
                                appName = appInfo.appName,
                                packageName = appInfo.packageName,
                                permissions = appInfo.permissions,
                                description = appInfo.description,
                                suspiciousApis = suspiciousApis
                            ) to entry
                            
                        } catch (e: OutOfMemoryError) {
                            println("⚠️ OOM during info extraction for ${entry.fileName}")
                            System.gc()
                            null
                        } catch (e: Exception) {
                            println("⚠️ Lỗi extract info ${entry.fileName}: ${e.message}")
                            null
                        }
                    }
                }

                if (apkInfoList.isNotEmpty()) {
                    // Call LLM API
                    val llmResults = GeminiApiHelper.analyzeBatchWithGemini(
                        apiKey = BuildConfig.GEMINI_API_KEY,
                        apkInfoList = apkInfoList.map { it.first }
                    )

                    // Process results
                    apkInfoList.forEachIndexed { index, (apkInfo, entry) ->
                        try {
                            val aiAnalysis = if (index < llmResults.size) llmResults[index] else "Lỗi: Không nhận được kết quả"
                            val riskLevel = extractRiskLevel(aiAnalysis)
                            
                            val dangerousPermissions = apkInfo.permissions.filter { permission ->
                                ApkAnalyzer.SUSPICIOUS_PERMISSIONS.any {
                                    permission.contains(it.replace("android.permission.", ""), ignoreCase = true)
                                }
                            }

                            val predictedLabel = when(riskLevel) {
                                RiskLevel.DANGEROUS, RiskLevel.UNKNOWN -> "MALWARE"
                                RiskLevel.SAFE -> "SAFE"
                            }

                            val result = AnalysisResult(
                                predictedLabel = predictedLabel,
                                riskLevel = riskLevel,
                                dangerousPermissions = dangerousPermissions,
                                summary = aiAnalysis,
                                appName = apkInfo.appName,
                                packageName = apkInfo.packageName,
                                suspiciousApis = apkInfo.suspiciousApis
                            )

                            results[entry.apkPath] = result
                            
                            // Cache with size limit
                            if (analysisCache.size < maxCacheSize) {
                                val cacheKey = "${entry.apkPath}_${File(entry.apkPath).lastModified()}"
                                analysisCache[cacheKey] = result
                            }

                        } catch (e: Exception) {
                            println("❌ Lỗi xử lý ${entry.fileName}: ${e.message}")
                        }
                    }
                }

            } catch (e: OutOfMemoryError) {
                println("💥 OOM in batch LLM analysis")
                // Emergency cleanup
                localTempFiles.forEach { it.delete() }
                cleanup()
                System.gc()
            } catch (e: Exception) {
                println("💥 Lỗi batch LLM: ${e.message}")
            } finally {
                // Clean up all temporary files for this batch
                localTempFiles.forEach { tempFile ->
                    try {
                        if (tempFile.exists()) {
                            tempFile.delete()
                        }
                        tempFiles.remove(tempFile)
                    } catch (e: Exception) {
                        println("⚠️ Không thể xóa temp file: ${tempFile.name}")
                    }
                }
            }

            return@withContext results
        }

    /**
     * Create CSV with proper resource management
     */
    private fun createResultsCSV(
        file: File,
        entries: List<DatasetEntry>,
        results: Map<String, AnalysisResult>
    ) {
        try {
            FileWriter(file).use { writer ->
                writer.append("APK_PATH,FILENAME,APP_NAME,PACKAGE_NAME,GROUND_TRUTH_LABEL,PREDICTED_LABEL,AI_RISK_LEVEL,")
                    .append("DANGEROUS_PERMISSIONS,SUSPICIOUS_APIS,ANALYSIS_SUMMARY\n")

                entries.forEach { entry ->
                    val result = results[entry.apkPath] ?: return@forEach
                    
                    val csvLine = "${entry.apkPath},${entry.fileName},${result.appName},${result.packageName},${entry.groundTruthLabel},"
                        .plus("${result.predictedLabel},${result.riskLevel.label},")
                        .plus("\"${result.dangerousPermissions.joinToString(";")}\",")
                        .plus("\"${result.suspiciousApis.joinToString(";")}\",")
                        .plus("\"${result.summary.replace("\"", "\"\"").replace("\n", " ")}\"\n")
                    
                    writer.append(csvLine)
                }
            }
        } catch (e: Exception) {
            println("❌ Lỗi tạo CSV: ${e.message}")
        }
    }

    /**
     * Create dataset CSV with proper resource management
     */
    private fun createDatasetCSV(file: File, entries: List<DatasetEntry>) {
        try {
            FileWriter(file).use { writer ->
                writer.append("APK_PATH,FILENAME,GROUND_TRUTH_LABEL,FILE_SIZE_KB\n")
                entries.forEach { entry ->
                    writer.append("${entry.apkPath},${entry.fileName},${entry.groundTruthLabel},${entry.fileSizeKB}\n")
                }
            }
        } catch (e: Exception) {
            println("❌ Lỗi tạo dataset CSV: ${e.message}")
        }
    }

    /**
     * Scans dataset directory and returns all APK files with their ground truth labels
     */
    private fun scanDatasetFolder(rootPath: String): List<DatasetEntry> {
        val root = File(rootPath)
        if (!root.exists() || !root.isDirectory) {
            throw IllegalArgumentException("Invalid dataset directory: $rootPath")
        }

        val entries = mutableListOf<DatasetEntry>()

        // Each subdirectory is a category (safe, malware, etc)
        root.listFiles { file -> file.isDirectory }?.forEach { categoryDir ->
            val groundTruthLabel = categoryDir.name.uppercase()

            // Get all APK files in this category
            categoryDir.listFiles { file -> file.name.endsWith(".apk", ignoreCase = true) }?.forEach { apkFile ->
                entries.add(DatasetEntry(
                    apkPath = apkFile.absolutePath,
                    fileName = apkFile.name,
                    groundTruthLabel = groundTruthLabel,
                    fileSizeKB = apkFile.length() / 1024
                ))
            }
        }

        return entries
    }

    /**
     * Extract risk level from AI analysis text
     */
    private fun extractRiskLevel(analysisText: String): RiskLevel {
        // Tìm kiếm theo định dạng chuẩn 
        val riskPattern = """MỨC\s+ĐỘ\s+RỦI\s+RO:\s*(AN\s+TOÀN|NGUY\s+HIỂM)""".toRegex(RegexOption.IGNORE_CASE)
        val matchResult = riskPattern.find(analysisText)
        
        if (matchResult != null) {
            val riskText = matchResult.groupValues[1].replace("\\s+".toRegex(), " ").trim()
            return when {
                riskText.equals("AN TOÀN", ignoreCase = true) -> RiskLevel.SAFE
                else -> RiskLevel.DANGEROUS
            }
        }
        
        // Phương pháp dự phòng
        val lines = analysisText.split("\n")
        for (line in lines) {
            if (line.contains("MỨC ĐỘ RỦI RO:", ignoreCase = true) || 
                line.contains("ĐÁNH GIÁ:", ignoreCase = true)) {
                return when {
                    line.contains("AN TOÀN", ignoreCase = true) -> RiskLevel.SAFE
                    else -> RiskLevel.DANGEROUS 
                }
            }
        }
        
        return when {
            analysisText.contains("AN TOÀN", ignoreCase = true) &&
            !analysisText.contains("KHÔNG AN TOÀN", ignoreCase = true) &&
            !analysisText.contains("NGUY HIỂM", ignoreCase = true) -> RiskLevel.SAFE
            else -> RiskLevel.DANGEROUS
        }
    }

    /**
     * Generate Python script for metrics calculation
     */
    private fun generatePythonScript(
        datasetPath: String,
        resultsPath: String,
        outputDir: String
    ): String {
        return """
            import pandas as pd
            import numpy as np
            import os
            from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            # Load data
            dataset_df = pd.read_csv("$datasetPath")
            results_df = pd.read_csv("$resultsPath")
            
            # Calculate metrics
            y_true = results_df['GROUND_TRUTH_LABEL']
            y_pred = results_df['PREDICTED_LABEL']
            
            # Basic metrics
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, pos_label='MALWARE', average='binary')
            recall = recall_score(y_true, y_pred, pos_label='MALWARE', average='binary')
            f1 = f1_score(y_true, y_pred, pos_label='MALWARE', average='binary')
            
            # Generate report
            print(f"Accuracy: {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall: {recall:.4f}")
            print(f"F1 Score: {f1:.4f}")
            
            print("\\nClassification Report:")
            print(classification_report(y_true, y_pred))
            
            # Create confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            plt.figure(figsize=(10, 8))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                        xticklabels=['SAFE', 'MALWARE'],
                        yticklabels=['SAFE', 'MALWARE'])
            plt.title('Confusion Matrix')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.tight_layout()
            plt.savefig("$outputDir/confusion_matrix.png")
            
            # Export misclassified samples
            errors_df = results_df[results_df['GROUND_TRUTH_LABEL'] != results_df['PREDICTED_LABEL']]
            errors_df.to_csv("$outputDir/misclassified_apks.csv", index=False)
            
            print(f"\\nMisclassified samples: {len(errors_df)}/{len(results_df)} ({len(errors_df)/len(results_df)*100:.2f}%)")
            
            # Summary file
            with open("$outputDir/metrics_summary.txt", "w") as f:
                f.write(f"APK Malware Detection Evaluation\\n")
                f.write(f"============================\\n\\n")
                f.write(f"Dataset: {len(results_df)} APK files\\n")
                f.write(f"Distribution: {dict(y_true.value_counts())}\\n\\n")
                f.write(f"Accuracy: {accuracy:.4f}\\n")
                f.write(f"Precision: {precision:.4f}\\n")
                f.write(f"Recall: {recall:.4f}\\n")
                f.write(f"F1 Score: {f1:.4f}\\n\\n")
                f.write("Classification Report:\\n")
                f.write(classification_report(y_true, y_pred))
            
            print(f"\\nResults saved to: $outputDir")
        """.trimIndent()
    }

    /**
     * Clean up temporary files
     */
    private fun cleanupTempFiles() {
        tempFiles.forEach { file ->
            try {
                if (file.exists()) {
                    file.delete()
                }
            } catch (e: Exception) {
                // Ignore cleanup errors
            }
        }
        tempFiles.clear()
    }

    /**
     * Clean up all resources
     */
    fun cleanup() {
        cleanupTempFiles()
        analysisCache.clear()
        analysisScope.cancel()
        System.gc()
    }

    // Data classes
    data class DatasetEntry(
        val apkPath: String,
        val fileName: String,
        val groundTruthLabel: String,
        val fileSizeKB: Long
    )

    data class AnalysisResult(
        val predictedLabel: String,
        val riskLevel: RiskLevel,
        val dangerousPermissions: List<String>,
        val summary: String,
        val appName: String = "",
        val packageName: String = "",
        val suspiciousApis: List<String> = emptyList()
    )
}