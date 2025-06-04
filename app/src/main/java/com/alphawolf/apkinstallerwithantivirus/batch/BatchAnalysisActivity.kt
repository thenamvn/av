package com.alphawolf.apkinstallerwithantivirus.batch

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.os.Bundle
import android.os.Environment
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.lifecycleScope
import com.alphawolf.apkinstallerwithantivirus.databinding.ActivityBatchAnalysisBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import androidx.constraintlayout.widget.ConstraintLayout
import com.alphawolf.apkinstallerwithantivirus.R 

class BatchAnalysisActivity : AppCompatActivity() {
    private lateinit var binding: ActivityBatchAnalysisBinding
    private var isAnalyzing = false
    private var batchAnalyzer: BatchApkAnalyzer? = null

    companion object {
        private const val PERMISSION_REQUEST_CODE = 1001
        private const val REQUEST_DATASET_DIR = 2001
        private const val MANAGE_STORAGE_REQUEST_CODE = 1002
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityBatchAnalysisBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        // Setup action bar with back button
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "APK Batch Analysis"
        
        setupUI()
    }

    // Handle back button press in action bar
    override fun onSupportNavigateUp(): Boolean {
        handleBackPress()
        return true
    }
    
    // Handle back button press
    override fun onBackPressed() {
        handleBackPress()
    }
    
    private fun handleBackPress() {
        if (isAnalyzing) {
            // Show confirmation dialog if analysis is running
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("⚠️ Đang phân tích")
                .setMessage("Batch analysis đang chạy. Bạn có muốn dừng và quay về không?")
                .setPositiveButton("Dừng và quay về") { _, _ ->
                    // Stop analysis and go back
                    stopAnalysis()
                    super.onBackPressed()
                }
                .setNegativeButton("Tiếp tục") { dialog, _ ->
                    dialog.dismiss()
                }
                .show()
        } else {
            super.onBackPressed()
        }
    }
    
    private fun stopAnalysis() {
        isAnalyzing = false
        batchAnalyzer?.cleanup()
        batchAnalyzer = null
        binding.progressBar.visibility = View.GONE
        binding.btnStartAnalysis.isEnabled = true
        // Force garbage collection
        System.gc()
    }

    private fun setupUI() {
        // Default paths
        val defaultDatasetPath = File(Environment.getExternalStorageDirectory(), "apk_dataset").absolutePath
        val defaultOutputPath = File(getExternalFilesDir(null), "test_results").absolutePath
        
        binding.edtDatasetPath.setText(defaultDatasetPath)
        binding.edtOutputPath.setText(defaultOutputPath)
        
        // Set default batch sizes with memory-safe limits
        binding.edtLlmBatchSize.setText("6") // Reduced from 8 for memory safety
        binding.edtParallelBatches.setText("2") // Keep at 2 for stability
        
        binding.btnStartAnalysis.setOnClickListener {
            if (checkPermissions()) {
                startBatchAnalysis()
            } else {
                requestPermissions()
            }
        }
    }

    private fun showHelpDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("📖 Hướng dẫn Batch Analysis")
            .setMessage("""
                🎯 MỤC ĐÍCH:
                Phân tích hàng loạt APK để đánh giá độ chính xác của hệ thống detection.
                
                📁 CẤU TRÚC THỨ MỤC:
                dataset/
                ├── safe/        (APK an toàn)
                └── malware/     (APK độc hại)
                
                ⚡ TỐI ƯU HÓA:
                • LLM Batch Size: Số APK phân tích cùng lúc (khuyến nghị: 4-8)
                • Parallel Batches: Số batch chạy song song (khuyến nghị: 1-2)
                
                📊 KẾT QUẢ:
                • CSV files với kết quả phân tích
                • Python script tính accuracy metrics
                • Confusion matrix và performance stats
                
                💡 MẸO:
                • Batch size 4-6 cho thiết bị RAM thấp
                • Batch size 6-8 cho thiết bị RAM cao
                • Parallel batches = 1 nếu gặp lỗi memory
            """.trimIndent())
            .setPositiveButton("Hiểu rồi") { dialog, _ -> 
                dialog.dismiss() 
            }
            .show()
    }

    private fun setupDefaultFolders(datasetPath: String) {
        try {
            val datasetDir = File(datasetPath)
            datasetDir.mkdirs()
            File(datasetDir, "safe").mkdir()
            File(datasetDir, "malware").mkdir()
        } catch (e: Exception) {
            // Log error if needed
        }
    }

    private fun openDocumentTree() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        startActivityForResult(intent, REQUEST_DATASET_DIR)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_DATASET_DIR && resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                // Save persistent permission to folder
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or
                            Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )

                // Save URI in SharedPreferences for later use
                getSharedPreferences("batch_analysis", MODE_PRIVATE).edit()
                    .putString("dataset_uri", uri.toString())
                    .apply()

                // Update UI with selected URI
                binding.edtDatasetPath.setText(uri.toString())

                // Create subfolders in selected directory
                createRequiredSubfolders(uri)
            }
        } else if (requestCode == MANAGE_STORAGE_REQUEST_CODE) {
            // Check permission again after user interaction with settings
            if (checkPermissions()) {
                startBatchAnalysis()
            } else {
                Toast.makeText(
                    this,
                    "Cần quyền truy cập bộ nhớ để đọc các file APK",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun createRequiredSubfolders(parentUri: Uri) {
        val safeDirName = "safe"
        val malwareDirName = "malware"

        try {
            val documentTree = DocumentFile.fromTreeUri(this, parentUri)
            if (documentTree == null) {
                Toast.makeText(this, "Không thể truy cập thư mục đã chọn", Toast.LENGTH_SHORT).show()
                return
            }

            // Check and track folder status
            val safeExists = documentTree.findFile(safeDirName) != null
            val malwareExists = documentTree.findFile(malwareDirName) != null

            // Create "safe" folder if it doesn't exist
            if (!safeExists) {
                val created = documentTree.createDirectory(safeDirName) != null
                if (!created) {
                    Toast.makeText(this, "Không thể tạo thư mục $safeDirName", Toast.LENGTH_SHORT).show()
                    return
                }
            }

            // Create "malware" folder if it doesn't exist
            if (!malwareExists) {
                val created = documentTree.createDirectory(malwareDirName) != null
                if (!created) {
                    Toast.makeText(this, "Không thể tạo thư mục $malwareDirName", Toast.LENGTH_SHORT).show()
                    return
                }
            }

            // Display appropriate message based on folder status
            val message = when {
                !safeExists && !malwareExists -> "Đã tạo thư mục safe và malware"
                !safeExists -> "Đã tạo thư mục safe, thư mục malware đã tồn tại"
                !malwareExists -> "Đã tạo thư mục malware, thư mục safe đã tồn tại"
                else -> "Các thư mục safe và malware đã tồn tại"
            }

            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

        } catch (e: Exception) {
            Toast.makeText(this, "Lỗi: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun requestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11+ requires MANAGE_EXTERNAL_STORAGE through Settings
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.addCategory("android.intent.category.DEFAULT")
                intent.data = Uri.parse("package:${applicationContext.packageName}")
                startActivityForResult(intent, MANAGE_STORAGE_REQUEST_CODE)
            } catch (e: Exception) {
                // If can't open specific settings page, open general settings
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                startActivityForResult(intent, MANAGE_STORAGE_REQUEST_CODE)
            }
        } else {
            // Android 10 and below
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
                PERMISSION_REQUEST_CODE
            )
        }
    }

    private fun checkPermissions(): Boolean {
        // Check All Files Access permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager()
        } else {
            return ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (requestCode == PERMISSION_REQUEST_CODE &&
            grantResults.isNotEmpty() &&
            grantResults[0] == PackageManager.PERMISSION_GRANTED
        ) {
            startBatchAnalysis()
        } else {
            Toast.makeText(
                this,
                "Storage permission is required to access APK files",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun startBatchAnalysis() {
        if (isAnalyzing) return

        val datasetPathText = binding.edtDatasetPath.text.toString()
        val outputPath = binding.edtOutputPath.text.toString()

        if (datasetPathText.isBlank() || outputPath.isBlank()) {
            Toast.makeText(this, "Please enter valid paths", Toast.LENGTH_SHORT).show()
            return
        }

        // Get batch configuration from UI with memory-safe limits
        val llmBatchSize = binding.edtLlmBatchSize.text.toString().toIntOrNull()?.coerceIn(1, 10) ?: 6
        val parallelBatches = binding.edtParallelBatches.text.toString().toIntOrNull()?.coerceIn(1, 3) ?: 2

        // Validate batch sizes with memory considerations
        if (llmBatchSize < 1 || llmBatchSize > 10) {
            Toast.makeText(this, "LLM batch size should be between 1-10 for memory safety", Toast.LENGTH_SHORT).show()
            return
        }
        if (parallelBatches < 1 || parallelBatches > 3) {
            Toast.makeText(this, "Parallel batches should be between 1-3 for memory safety", Toast.LENGTH_SHORT).show()
            return
        }

        // Check if path is SAF URI
        if (datasetPathText.startsWith("content://")) {
            handleSAFPath(datasetPathText, outputPath, llmBatchSize, parallelBatches)
        } else {
            handleRegularPath(datasetPathText, outputPath, llmBatchSize, parallelBatches)
        }
    }

    private fun handleSAFPath(
        datasetPathText: String,
        outputPath: String,
        llmBatchSize: Int,
        parallelBatches: Int
    ) {
        // Handle SAF URI path
        val uri = Uri.parse(datasetPathText)
        try {
            val documentTree = DocumentFile.fromTreeUri(this, uri)
            if (documentTree == null || !documentTree.exists()) {
                Toast.makeText(this, "Invalid dataset URI", Toast.LENGTH_SHORT).show()
                return
            }

            // Check folder structure
            val safeDir = documentTree.findFile("safe")
            val malwareDir = documentTree.findFile("malware")

            if (safeDir == null || malwareDir == null) {
                Toast.makeText(this,
                    "Thiếu thư mục safe hoặc malware. Vui lòng chọn lại thư mục.",
                    Toast.LENGTH_LONG).show()
                return
            }

            // Find APK files
            val safeApks = safeDir.listFiles().filter { it.name?.endsWith(".apk", true) == true }
            val malwareApks = malwareDir.listFiles().filter { it.name?.endsWith(".apk", true) == true }

            if (safeApks.isEmpty() && malwareApks.isEmpty()) {
                Toast.makeText(this,
                    "Không tìm thấy file APK nào. Vui lòng thêm file APK vào thư mục safe và/hoặc malware.",
                    Toast.LENGTH_LONG).show()
                return
            }

            Toast.makeText(this,
                "Xử lý URI từ SAF chưa được hỗ trợ. Vui lòng sử dụng đường dẫn file thông thường.",
                Toast.LENGTH_LONG).show()

        } catch (e: Exception) {
            Toast.makeText(this, "Lỗi truy cập thư mục: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun handleRegularPath(
        datasetPathText: String,
        outputPath: String,
        llmBatchSize: Int,
        parallelBatches: Int
    ) {
        // Handle regular file path
        val datasetDir = File(datasetPathText)
        if (!datasetDir.exists()) {
            Toast.makeText(this, "Dataset directory does not exist. Creating it now.", Toast.LENGTH_LONG).show()
            val success = datasetDir.mkdirs()
            if (!success) {
                Toast.makeText(this, "Failed to create dataset directory", Toast.LENGTH_SHORT).show()
                return
            }
        } else if (!datasetDir.isDirectory) {
            Toast.makeText(this, "Invalid dataset path - not a directory", Toast.LENGTH_SHORT).show()
            return
        }

        // Check dataset structure
        val hasValidStructure = checkAndCreateDatasetStructure(datasetDir)
        if (!hasValidStructure) {
            return
        }

        // Check for APK files
        val safeDir = File(datasetDir, "safe")
        val malwareDir = File(datasetDir, "malware")

        val safeApks = safeDir.listFiles { _, name -> name.endsWith(".apk", true) }?.size ?: 0
        val malwareApks = malwareDir.listFiles { _, name -> name.endsWith(".apk", true) }?.size ?: 0

        if (safeApks == 0 && malwareApks == 0) {
            Toast.makeText(this,
                "Không tìm thấy file APK nào. Vui lòng thêm file APK vào thư mục safe và/hoặc malware.",
                Toast.LENGTH_LONG).show()
            return
        }

        // Start analysis
        startAnalysisProcess(datasetPathText, outputPath, llmBatchSize, parallelBatches)
    }

    private fun startAnalysisProcess(
        datasetPath: String,
        outputPath: String,
        llmBatchSize: Int,
        parallelBatches: Int
    ) {
        isAnalyzing = true
        binding.progressBar.visibility = View.VISIBLE
        binding.progressBar.isIndeterminate = true
        binding.btnStartAnalysis.isEnabled = false
        binding.tvStatus.text = "Starting batch analysis..."

        lifecycleScope.launch {
            try {
                batchAnalyzer = BatchApkAnalyzer(
                    context = applicationContext,
                    llmBatchSize = llmBatchSize,
                    parallelBatchSize = parallelBatches
                )
                
                // Set up progress callback for real-time updates
                batchAnalyzer?.setProgressCallback(object : BatchApkAnalyzer.ProgressCallback {
                    override fun onProgress(current: Int, total: Int, message: String) {
                        runOnUiThread {
                            binding.tvStatus.text = "⚡ $message\n\n" +
                                "🔧 Batch Config: $llmBatchSize APKs per LLM call, $parallelBatches parallel batches\n" +
                                "💡 Memory Optimization: Smart chunking and cleanup enabled"
                            
                            // Update progress bar if it's not indeterminate
                            if (total > 0) {
                                binding.progressBar.isIndeterminate = false
                                binding.progressBar.max = total
                                binding.progressBar.progress = current
                            }
                        }
                    }
                })
                
                val result = withContext(Dispatchers.IO) {
                    batchAnalyzer?.analyzeDatasetAndGenerateReport(
                        datasetRootPath = datasetPath,
                        outputPath = outputPath
                    ) ?: "Error: Analyzer not initialized"
                }

                if (result.startsWith("Phân tích hoàn tất!")) {
                    val optimizationStats = calculateOptimizationStats(llmBatchSize, parallelBatches)
                    binding.tvStatus.text = "🎉 Analysis Complete!\n\n$result\n\n$optimizationStats"
                } else {
                    binding.tvStatus.text = result
                }
                
            } catch (e: OutOfMemoryError) {
                binding.tvStatus.text = "❌ Out of Memory Error! Try reducing batch size to 3-4 and parallel batches to 1."
            } catch (e: Exception) {
                binding.tvStatus.text = "❌ Error: ${e.message}"
            } finally {
                // Cleanup
                batchAnalyzer?.cleanup()
                batchAnalyzer = null
                binding.progressBar.visibility = View.GONE
                binding.progressBar.isIndeterminate = true
                binding.btnStartAnalysis.isEnabled = true
                isAnalyzing = false
                
                // Force garbage collection
                System.gc()
            }
        }
    }
    
    private fun calculateOptimizationStats(llmBatchSize: Int, parallelBatches: Int): String {
        return """
        ⚡ OPTIMIZATION SUMMARY:
        ═══════════════════════
        🔧 LLM Batch Size: $llmBatchSize APKs per API call
        🚀 Parallel Processing: $parallelBatches batches simultaneously
        💡 API Call Reduction: ~${((llmBatchSize - 1) * 100 / llmBatchSize)}% fewer calls vs individual analysis
        📈 Expected Speed Improvement: ${llmBatchSize}x faster processing
        🎯 Memory Efficiency: Smart chunking and temp file cleanup
        """.trimIndent()
    }

    private fun checkAndCreateDatasetStructure(datasetDir: File): Boolean {
        val requiredDirs = listOf("safe", "malware")
        val existingDirs = datasetDir.listFiles()
            ?.filter { it.isDirectory }
            ?.map { it.name.lowercase() }
            ?: emptyList()

        // Check missing directories
        val missingDirs = requiredDirs.filter { requiredDir ->
            !existingDirs.any { it == requiredDir }
        }

        if (missingDirs.isEmpty()) {
            return true // Valid structure
        }

        // Show message and create missing directories
        val message = StringBuilder("Dataset cần có cấu trúc thư mục con:\n")
        var creationSuccess = true

        missingDirs.forEach { dirName ->
            val dirToCreate = File(datasetDir, dirName)
            message.append("- $dirName: ")

            val success = dirToCreate.mkdir()
            if (success) {
                message.append("Đã tạo thành công\n")
            } else {
                message.append("Không thể tạo\n")
                creationSuccess = false
            }
        }

        Toast.makeText(this, message.toString(), Toast.LENGTH_LONG).show()
        return creationSuccess
    }

    override fun onDestroy() {
        super.onDestroy()
        // Cleanup when activity is destroyed
        batchAnalyzer?.cleanup()
        batchAnalyzer = null
    }
}