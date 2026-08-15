#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <functional>
#include <unordered_map>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/ringbuf.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "psram_allocator.h"

// Filesystem Task Delegate
// Handles filesystem operations that require INTERNAL_RAM stack
// to avoid ESP32 cache disable crashes when called from PSRAM tasks
class FilesystemTaskDelegate {
public:
    // Operation types that can be delegated
    enum class OperationType {
        FILE_ROTATION,      // File rotation with backup creation
        DIRECTORY_CREATE,   // Directory creation
        FILE_DELETE,        // File deletion
        FILE_STATS,         // File size/existence checks
        LIST_FILES,         // List files in directory
        CLEANUP_ORPHANS,    // Cleanup orphan files with age threshold
        FILE_WRITE,         // Write file with PSRAM data
        FILE_READ,          // Read file to PSRAM data
        FILE_TRIM,          // Trim file to specified size (keep newest data)
        STREAM_FILE,        // produce-chunk streaming to a caller-provided queue
        PSRAM_STREAM        // NEW: Hybrid PSRAM-backed streaming (BEST!)
    };

    // Max chunk size for streaming (fits comfortably in internal RAM queue items)
    static constexpr size_t STREAM_CHUNK_MAX = 1024;

    // Hybrid PSRAM-backed Ring Buffer Configuration
    static constexpr size_t PSRAM_RING_SIZE = 128 * 1024;  // 128KB ring buffer in PSRAM
    static constexpr size_t DRAM_STAGING_SIZE = 2048;      // 2KB staging buffer in DRAM
    static constexpr size_t CIRCULAR_QUEUE_SIZE = 16;      // Circular descriptor queue size
    static constexpr const char* EOF_SENTINEL = "EOF_SENTINEL";

    // Circular queue slot states
    enum class SlotState : uint8_t {
        EMPTY = 0,      // Slot is empty and available for producer
        READY = 1,      // Slot has data ready for consumer
        CONSUMED = 2    // Slot has been consumed and can be reused
    };

    // Lightweight descriptor for PSRAM ring buffer chunks (stored in DRAM)
    struct RingDescriptor {
        uint32_t offset;    // Position in PSRAM ring buffer
        uint16_t length;    // Number of bytes in this chunk
        bool eof;           // True when stream finished
        SlotState state;    // Current state of this slot
        uint32_t sequence;  // Sequence number for ordering
    };

    // Legacy chunk structure for existing streaming API
    struct StreamChunk {
        size_t len;     // bytes valid in data[]
        int    status;  // 0 ok, <0 error
        bool   eof;     // true when stream finished
        uint8_t data[STREAM_CHUNK_MAX];
    };

    /**
     * Start streaming a file to a queue. All flash I/O happens in the delegate task (DRAM stack).
     * The caller (e.g., httpd handler) must xQueueReceive(StreamChunk) until eof==true.
     * Returns ESP_OK if the stream is started (file opened), otherwise error.
     */
    esp_err_t startFileStreaming(const std::string& file_path,
                                 QueueHandle_t out_queue,
                                 size_t chunk_size = STREAM_CHUNK_MAX,
                                 uint32_t timeout_ms = 3000);

    /**
     * NEW: Hybrid PSRAM-backed streaming with circular queue - BEST approach!
     * Producer (delegate with DRAM stack) reads via staging buffer to PSRAM ring
     * Consumer (webserver with PSRAM stack) gets descriptors via getNextDescriptor()
     * Returns true if streaming started successfully
     */
    bool startPSRAMStreaming(const char* file_path,
                             uint32_t timeout_ms = 5000,
                             int tail_lines = 0);  // 0 = read entire file, >0 = read last N lines

    /**
     * Get access to the PSRAM ring buffer for reading (consumer side)
     * Returns pointer to the PSRAM ring buffer
     */
    uint8_t* getPSRAMRingBuffer() const;

    /**
     * Circular queue management for consumer
     * Returns the next available descriptor, or nullptr if none available
     */
    RingDescriptor* getNextDescriptor(uint32_t timeout_ms = 1000);

    /**
     * Mark a descriptor as consumed so it can be reused
     */
    void markDescriptorConsumed(RingDescriptor* desc);

    // Result codes for delegated operations
    enum class OperationResult {
        SUCCESS = 0,
        FAILURE = 1,
        TIMEOUT = 2,
        INVALID_PARAMS = 3
    };

    // Message structure for task communication
    struct DelegationMessage {
        OperationType operation;
        char file_path[256];        // Primary file path
        char backup_path[256];      // Backup path (for rotation)
        uint32_t max_files;         // Max backup files to keep
        size_t rotate_bytes;        // Size threshold for rotation
        uint64_t age_threshold_ms;  // Age threshold for orphan cleanup (milliseconds)
        uint32_t request_id;        // Unique request identifier
        TickType_t timeout_ticks;   // Operation timeout
        size_t stream_chunk_size;
        QueueHandle_t stream_queue; // where to push StreamChunk
        RingbufHandle_t ring_buffer; // for zero-copy streaming
        int tail_lines;             // 0 = read entire file, >0 = read last N lines
    };

    // Response structure
    struct DelegationResponse {
        uint32_t request_id;
        OperationResult result;
        esp_err_t esp_error;
        char error_message[64];     // Reduced from 128 to 64 bytes
        uint32_t file_count;        // Number of files found (for LIST_FILES)
        char file_list[1024];       // Reduced from 2048 to 1024 bytes
        size_t file_size;
        bool file_exists;
    };

    // Extended structures for file I/O operations
    struct FileIORequest {
        uint32_t request_id;
        OperationType operation;
        char file_path[256];
        psram_string* psram_data;      // Pointer to PSRAM data (for write operations)
        std::function<void(bool)>* callback; // Callback for async operations
        TickType_t timeout_ticks;
    };

    struct FileIOResponse {
        uint32_t request_id;
        OperationResult result;
        esp_err_t esp_error;
        psram_string psram_content;    // File content in PSRAM (for read operations)
    };

    // Singleton access
    static FilesystemTaskDelegate& getInstance();

    // Lifecycle
    bool initialize();
    void shutdown();

    // Core delegation methods
    OperationResult rotateFileSync(const std::string& file_path,
                                  size_t rotate_bytes,
                                  uint32_t max_files,
                                  uint32_t timeout_ms = 5000);

    OperationResult createDirectorySync(const std::string& dir_path,
                                      uint32_t timeout_ms = 2000);

    OperationResult deleteFileSync(const std::string& file_path,
                                 uint32_t timeout_ms = 2000);

    OperationResult listFilesSync(const std::string& dir_path,
                                std::vector<std::string>& file_list,
                                uint32_t timeout_ms = 3000);

    OperationResult cleanupOrphanFilesSync(const std::string& dir_path,
                                         uint64_t age_threshold_ms,
                                         uint32_t timeout_ms = 5000);

    OperationResult trimFileSync(const std::string& file_path,
                               size_t max_size_bytes,
                               uint32_t timeout_ms = 5000);

    // Async versions (fire and forget)
    bool rotateFileAsync(const std::string& file_path,
                        size_t rotate_bytes,
                        uint32_t max_files);

    bool trimFileAsync(const std::string& file_path,
                      size_t max_size_bytes);

    // File I/O operations for PSRAMReliableQueue
    bool readFileSync(const std::string& file_path, psram_string& content, uint32_t timeout_ms = 5000);
    bool writeFileSync(const std::string& file_path, const psram_string& content, uint32_t timeout_ms = 5000);

    // Async file operations with callbacks
    bool writeFileAsync(const std::string& file_path, const psram_string& content,
                       std::function<void(bool)> callback);

    // Streaming operations for safe concurrent access during file trimming
    bool openFileForStreaming(const std::string& file_path, void** file_handle);
    size_t readStreamChunk(void* file_handle, char* buffer, size_t chunk_size);
    void closeFileStream(void* file_handle);

    // Status and monitoring
    bool isReady() const { return initialized_ && task_handle_ != nullptr; }
    uint32_t getPendingOperations() const;

private:
    FilesystemTaskDelegate() = default;
    ~FilesystemTaskDelegate() = default;
    FilesystemTaskDelegate(const FilesystemTaskDelegate&) = delete;
    FilesystemTaskDelegate& operator=(const FilesystemTaskDelegate&) = delete;

    // Internal implementation
    static void taskMain(void* params);
    void processMessages();

    bool sendRequestAndWait(const DelegationMessage& msg,
                            DelegationResponse& response,
                            uint32_t timeout_ms);
    bool processFileStatsMessage(const DelegationMessage& msg, DelegationResponse& resp);
    bool processStreamFileMessage(const DelegationMessage& msg, DelegationResponse& resp);
    bool processPSRAMStreamMessage(const DelegationMessage& msg, DelegationResponse& resp);
    bool processRotationMessage(const DelegationMessage& msg, DelegationResponse& response);
    bool processDirectoryMessage(const DelegationMessage& msg, DelegationResponse& response);
    bool processDeleteMessage(const DelegationMessage& msg, DelegationResponse& response);
    bool processListFilesMessage(const DelegationMessage& msg, DelegationResponse& response);
    bool processCleanupOrphansMessage(const DelegationMessage& msg, DelegationResponse& response);
    bool processTrimFileMessage(const DelegationMessage& msg, DelegationResponse& response);

    // File I/O processing methods
    bool processFileIORequest(const FileIORequest& req, FileIOResponse& response);
    bool writeFileInternal(const std::string& file_path, const psram_string& content);
    bool readFileInternal(const std::string& file_path, psram_string& content);

    uint32_t generateRequestId();
    bool sendRequest(const DelegationMessage& msg, uint32_t timeout_ms);
    bool waitForResponse(uint32_t request_id, DelegationResponse& response, uint32_t timeout_ms);

    // Task and communication
    TaskHandle_t task_handle_ = nullptr;
    QueueHandle_t request_queue_ = nullptr;
    QueueHandle_t response_queue_ = nullptr;

    // State management
    bool initialized_ = false;
    std::mutex state_mutex_;
    uint32_t next_request_id_ = 1;

    // File I/O management
    std::mutex fileio_mutex_;
    QueueHandle_t fileio_request_queue_ = nullptr;
    QueueHandle_t fileio_response_queue_ = nullptr;
    std::unordered_map<uint32_t, std::function<void(bool)>> async_callbacks_;

    // Hybrid PSRAM-backed streaming infrastructure
    uint8_t* psram_ring_buffer_ = nullptr;          // 128KB ring buffer in PSRAM
    uint8_t* dram_staging_buffer_ = nullptr;        // 2KB staging buffer in DRAM
    RingDescriptor* circular_descriptors_ = nullptr; // Circular array of descriptors in DRAM
    SemaphoreHandle_t ring_mutex_ = nullptr;        // Mutex for ring buffer access
    StaticSemaphore_t ring_mutex_buffer_;           // Static semaphore buffer
    SemaphoreHandle_t streaming_semaphore_ = nullptr;   // Binary semaphore for serializing concurrent streaming requests
    StaticSemaphore_t streaming_semaphore_buffer_;      // Static semaphore buffer
    volatile uint32_t ring_head_ = 0;               // Producer position (DRAM)
    volatile uint32_t ring_tail_ = 0;               // Consumer position (DRAM)
    volatile uint32_t producer_index_ = 0;          // Producer slot index in circular queue
    volatile uint32_t consumer_index_ = 0;          // Consumer slot index in circular queue
    volatile uint32_t sequence_counter_ = 0;        // Global sequence counter

    // Configuration
    static constexpr size_t REQUEST_QUEUE_SIZE = 10;   // Increased back to 10 for streaming support
    static constexpr size_t RESPONSE_QUEUE_SIZE = 10;  // Increased back to 10 for streaming support
    static constexpr uint32_t TASK_STACK_SIZE = 8192;  // 8KB in INTERNAL_RAM
    static constexpr UBaseType_t TASK_PRIORITY = 8;    // High priority for filesystem ops
    static constexpr const char* TASK_NAME = "fs_delegate";
};