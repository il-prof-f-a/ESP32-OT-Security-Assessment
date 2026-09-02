#include "filesystem_task_delegate.h"
#include "logging_system.h"
#include "task_config.h"
#include "async_storage_engine.h"
#include "psram_allocator.h"
#include <sys/stat.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <dirent.h>

extern "C" {
    #include "esp_psram.h"
    #include "esp_timer.h"
    #include "esp_heap_caps.h"
}

static const char* TAG = "FSDelegate";

static const char* opTypeToString(FilesystemTaskDelegate::OperationType type) {
    switch (type) {
        case FilesystemTaskDelegate::OperationType::FILE_ROTATION: return "FILE_ROTATION";
        case FilesystemTaskDelegate::OperationType::DIRECTORY_CREATE: return "DIRECTORY_CREATE";
        case FilesystemTaskDelegate::OperationType::FILE_DELETE: return "FILE_DELETE";
        case FilesystemTaskDelegate::OperationType::STREAM_FILE: return "STREAM_FILE";
        case FilesystemTaskDelegate::OperationType::PSRAM_STREAM: return "PSRAM_STREAM";
        case FilesystemTaskDelegate::OperationType::FILE_STATS: return "FILE_STATS";
        case FilesystemTaskDelegate::OperationType::LIST_FILES: return "LIST_FILES";
        case FilesystemTaskDelegate::OperationType::CLEANUP_ORPHANS: return "CLEANUP_ORPHANS";
        case FilesystemTaskDelegate::OperationType::FILE_WRITE: return "FILE_WRITE";
        case FilesystemTaskDelegate::OperationType::FILE_READ: return "FILE_READ";
        case FilesystemTaskDelegate::OperationType::FILE_TRIM: return "FILE_TRIM";
        default: return "UNKNOWN";
    }
}

// Utility function to check if current task is running on PSRAM stack
static bool isCurrentTaskOnPSRAMStack() {
    char stack_var = 0;  // Initialize to suppress warning
    return esp_ptr_external_ram(&stack_var);
}

FilesystemTaskDelegate& FilesystemTaskDelegate::getInstance() {
    static FilesystemTaskDelegate instance;
    return instance;
}

bool FilesystemTaskDelegate::initialize() {
    std::lock_guard<std::mutex> lock(state_mutex_);

    if (initialized_) {
        LOG_WARNING(TAG, "FilesystemTaskDelegate already initialized");
        return true;
    }

    LOG_INFO(TAG, "Initializing FilesystemTaskDelegate...");

    // Create message queues
    request_queue_ = xQueueCreate(REQUEST_QUEUE_SIZE, sizeof(DelegationMessage));
    if (!request_queue_) {
        LOG_ERROR(TAG, "Failed to create request queue");
        return false;
    }

    response_queue_ = xQueueCreate(RESPONSE_QUEUE_SIZE, sizeof(DelegationResponse));
    if (!response_queue_) {
        LOG_ERROR(TAG, "Failed to create response queue");
        vQueueDelete(request_queue_);
        request_queue_ = nullptr;
        return false;
    }

    // Create file I/O queues
    fileio_request_queue_ = xQueueCreate(REQUEST_QUEUE_SIZE, sizeof(FileIORequest));
    if (!fileio_request_queue_) {
        LOG_ERROR(TAG, "Failed to create file I/O request queue");
        vQueueDelete(request_queue_);
        vQueueDelete(response_queue_);
        request_queue_ = nullptr;
        response_queue_ = nullptr;
        return false;
    }

    fileio_response_queue_ = xQueueCreate(RESPONSE_QUEUE_SIZE, sizeof(FileIOResponse*));
    if (!fileio_response_queue_) {
        LOG_ERROR(TAG, "Failed to create file I/O response queue");
        vQueueDelete(request_queue_);
        vQueueDelete(response_queue_);
        vQueueDelete(fileio_request_queue_);
        request_queue_ = nullptr;
        response_queue_ = nullptr;
        fileio_request_queue_ = nullptr;
        return false;
    }

    // Create hybrid PSRAM-backed streaming infrastructure
    psram_ring_buffer_ = (uint8_t*)PSRAMUtils::allocatePreferred(PSRAM_RING_SIZE);
    if (!psram_ring_buffer_) {
        LOG_ERROR(TAG, "Failed to allocate PSRAM ring buffer");
        vQueueDelete(request_queue_);
        vQueueDelete(response_queue_);
        vQueueDelete(fileio_request_queue_);
        vQueueDelete(fileio_response_queue_);
        request_queue_ = nullptr;
        response_queue_ = nullptr;
        fileio_request_queue_ = nullptr;
        fileio_response_queue_ = nullptr;
        return false;
    }

    dram_staging_buffer_ = (uint8_t*)heap_caps_malloc(DRAM_STAGING_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!dram_staging_buffer_) {
        LOG_ERROR(TAG, "Failed to allocate DRAM staging buffer");
        heap_caps_free(psram_ring_buffer_);
        psram_ring_buffer_ = nullptr;
        vQueueDelete(request_queue_);
        vQueueDelete(response_queue_);
        vQueueDelete(fileio_request_queue_);
        vQueueDelete(fileio_response_queue_);
        request_queue_ = nullptr;
        response_queue_ = nullptr;
        fileio_request_queue_ = nullptr;
        fileio_response_queue_ = nullptr;
        return false;
    }

    // Allocate circular descriptor array in DRAM
    circular_descriptors_ = (RingDescriptor*)heap_caps_malloc(
        CIRCULAR_QUEUE_SIZE * sizeof(RingDescriptor),
        MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT
    );
    if (!circular_descriptors_) {
        LOG_ERROR(TAG, "Failed to allocate circular descriptor array");
        heap_caps_free(psram_ring_buffer_);
        heap_caps_free(dram_staging_buffer_);
        psram_ring_buffer_ = nullptr;
        dram_staging_buffer_ = nullptr;
        vQueueDelete(request_queue_);
        vQueueDelete(response_queue_);
        vQueueDelete(fileio_request_queue_);
        vQueueDelete(fileio_response_queue_);
        request_queue_ = nullptr;
        response_queue_ = nullptr;
        fileio_request_queue_ = nullptr;
        fileio_response_queue_ = nullptr;
        return false;
    }

    // Initialize all slots as empty
    for (int i = 0; i < CIRCULAR_QUEUE_SIZE; i++) {
        circular_descriptors_[i].state = SlotState::EMPTY;
        circular_descriptors_[i].sequence = 0;
        circular_descriptors_[i].offset = 0;
        circular_descriptors_[i].length = 0;
        circular_descriptors_[i].eof = false;
    }

    // Initialize circular queue indices
    producer_index_ = 0;
    consumer_index_ = 0;
    sequence_counter_ = 1;

    ring_mutex_ = xSemaphoreCreateMutexStatic(&ring_mutex_buffer_);
    if (!ring_mutex_) {
        LOG_ERROR(TAG, "Failed to create ring buffer mutex");
        heap_caps_free(psram_ring_buffer_);
        heap_caps_free(dram_staging_buffer_);
        heap_caps_free(circular_descriptors_);
        return false;
    }

    // Create streaming serialization binary semaphore (prevents concurrent streaming requests)
    // Binary semaphore avoids priority inheritance issues across different task contexts
    streaming_semaphore_ = xSemaphoreCreateBinaryStatic(&streaming_semaphore_buffer_);
    if (!streaming_semaphore_) {
        LOG_ERROR(TAG, "Failed to create streaming serialization semaphore");
        heap_caps_free(psram_ring_buffer_);
        heap_caps_free(dram_staging_buffer_);
        heap_caps_free(circular_descriptors_);
        vSemaphoreDelete(ring_mutex_);
        return false;
    }
    // Initialize semaphore as available (give it once so first request can take it)
    xSemaphoreGive(streaming_semaphore_);

    LOG_INFO(TAG, "PSRAM streaming: 128KB ring + 2KB staging created");

    // Create task in INTERNAL_RAM with high priority
    task_handle_ = TaskConfig::createTask(
        taskMain,
        TASK_NAME,
        TaskConfig::Presets::FILESYSTEM_DELEGATE,
        this
    );

    if (!task_handle_) {
        LOG_ERROR(TAG, "Failed to create filesystem delegate task");
        vQueueDelete(request_queue_);
        vQueueDelete(response_queue_);
        request_queue_ = nullptr;
        response_queue_ = nullptr;
        return false;
    }

    initialized_ = true;
    LOG_INFO(TAG, "✅ FilesystemTaskDelegate initialized successfully");

    return true;
}

void FilesystemTaskDelegate::shutdown() {
    std::lock_guard<std::mutex> lock(state_mutex_);

    // Rollback may run after a partial initialization failed before the
    // initialized_ flag was set.  Release every resource independently so a
    // failed boot cannot leak queues/buffers or leave a stale task alive.
    const bool had_resources = initialized_ || task_handle_ || request_queue_ ||
                               response_queue_ || fileio_request_queue_ ||
                               fileio_response_queue_ || psram_ring_buffer_ ||
                               dram_staging_buffer_ || circular_descriptors_ ||
                               ring_mutex_ || streaming_semaphore_;
    if (!had_resources) return;

    LOG_INFO(TAG, "Shutting down FilesystemTaskDelegate...");

    if (task_handle_) {
        vTaskDelete(task_handle_);
        task_handle_ = nullptr;
    }

    if (request_queue_) {
        vQueueDelete(request_queue_);
        request_queue_ = nullptr;
    }

    if (response_queue_) {
        vQueueDelete(response_queue_);
        response_queue_ = nullptr;
    }

    if (fileio_request_queue_) {
        vQueueDelete(fileio_request_queue_);
        fileio_request_queue_ = nullptr;
    }

    if (fileio_response_queue_) {
        vQueueDelete(fileio_response_queue_);
        fileio_response_queue_ = nullptr;
    }

    // Cleanup hybrid PSRAM streaming infrastructure
    if (psram_ring_buffer_) {
        heap_caps_free(psram_ring_buffer_);
        psram_ring_buffer_ = nullptr;
    }

    if (dram_staging_buffer_) {
        heap_caps_free(dram_staging_buffer_);
        dram_staging_buffer_ = nullptr;
    }

    if (circular_descriptors_) {
        heap_caps_free(circular_descriptors_);
        circular_descriptors_ = nullptr;
    }

    if (ring_mutex_) {
        vSemaphoreDelete(ring_mutex_);
        ring_mutex_ = nullptr;
    }

    if (streaming_semaphore_) {
        vSemaphoreDelete(streaming_semaphore_);
        streaming_semaphore_ = nullptr;
    }

    // Reset ring positions
    ring_head_ = 0;
    ring_tail_ = 0;

    // Clear async callbacks
    {
        std::lock_guard<std::mutex> fileio_lock(fileio_mutex_);
        async_callbacks_.clear();
    }

    initialized_ = false;
    LOG_INFO(TAG, "FilesystemTaskDelegate shutdown complete");
}

void FilesystemTaskDelegate::taskMain(void* params) {
    auto* delegate = static_cast<FilesystemTaskDelegate*>(params);

    // Verify we're running on INTERNAL_RAM stack
    if (isCurrentTaskOnPSRAMStack()) {
        LOG_ERROR(TAG, "🔴 CRITICAL: FilesystemTaskDelegate running on PSRAM stack!");
        vTaskDelete(nullptr);
        return;
    }

    LOG_INFO(TAG, "✅ FilesystemTaskDelegate task started on INTERNAL_RAM stack");

    delegate->processMessages();
}

void FilesystemTaskDelegate::processMessages() {
    DelegationMessage msg;
    DelegationResponse response;
    FileIORequest fileio_req;

    while (true) {
        // Check for file I/O requests first (higher priority)
        if (xQueueReceive(fileio_request_queue_, &fileio_req, 0) == pdTRUE) {
            // Allocate the response on the heap and hand it over by pointer: the
            // queue copies its item by memcpy, which would shallow-copy the
            // psram_string member and double-free it. The consumer owns and
            // deletes the pointer.
            FileIOResponse* fileio_resp = new FileIOResponse();
            fileio_resp->request_id = fileio_req.request_id;
            fileio_resp->result = OperationResult::FAILURE;

            bool success = processFileIORequest(fileio_req, *fileio_resp);

            // Send response
            if (xQueueSend(fileio_response_queue_, &fileio_resp, pdMS_TO_TICKS(100)) != pdTRUE) {
                delete fileio_resp;
                LOG_ERRORF(TAG, "Failed to send file I/O response for request %u", fileio_req.request_id);
            }

            // Handle async callback if present
            if (fileio_req.callback && fileio_req.operation == OperationType::FILE_WRITE) {
                std::lock_guard<std::mutex> lock(fileio_mutex_);
                auto it = async_callbacks_.find(fileio_req.request_id);
                if (it != async_callbacks_.end()) {
                    auto callback = it->second;
                    async_callbacks_.erase(it);
                    // Execute callback outside of lock
                    if (callback) callback(success);
                }
            }

            continue; // Process next message
        }

        // Clear message buffer to prevent corruption
        memset(&msg, 0, sizeof(msg));

        // Wait for incoming standard requests
        if (xQueueReceive(request_queue_, &msg, pdMS_TO_TICKS(10)) == pdTRUE) {

            // Check response queue space before processing to prevent deadlock
            UBaseType_t response_pending = uxQueueMessagesWaiting(response_queue_);
            if (response_pending >= (RESPONSE_QUEUE_SIZE - 1)) {
                LOG_WARNING(TAG, "Response queue full, dropping oldest response");
                DelegationResponse dummy;
                xQueueReceive(response_queue_, &dummy, 0);  // Remove oldest
            }

            // Initialize response safely
            memset(&response, 0, sizeof(response));
            response.request_id = msg.request_id;
            response.result = OperationResult::FAILURE;
            response.esp_error = ESP_FAIL;

            // Debug logging disabled for compilation
            // UBaseType_t pending_req = request_queue_ ? uxQueueMessagesWaiting(request_queue_) : 0;
            // opTypeToString(msg.operation), msg.request_id, msg.file_path, msg.rotate_bytes, msg.max_files, pending_req, msg.timeout_ticks

            // Process based on operation type
            bool success = false;
            switch (msg.operation) {
                case OperationType::FILE_ROTATION:
                    success = processRotationMessage(msg, response);
                    break;

                case OperationType::DIRECTORY_CREATE:
                    success = processDirectoryMessage(msg, response);
                    break;

                case OperationType::FILE_DELETE:
                    success = processDeleteMessage(msg, response);
                    break;

                case OperationType::LIST_FILES:
                    success = processListFilesMessage(msg, response);
                    break;

                case OperationType::CLEANUP_ORPHANS:
                    success = processCleanupOrphansMessage(msg, response);
                    break;

                case OperationType::FILE_TRIM:
                    success = processTrimFileMessage(msg, response);
                    break;

                case OperationType::FILE_STATS:
                    success = processFileStatsMessage(msg, response);
                    break;

                case OperationType::STREAM_FILE:
                    success = processStreamFileMessage(msg, response);
                    break;

                case OperationType::PSRAM_STREAM:
                    success = processPSRAMStreamMessage(msg, response);
                    break;

                default:
                    snprintf(response.error_message, sizeof(response.error_message),
                            "Unknown operation type: %d", (int)msg.operation);
                    break;
            }

            if (success) {
                response.result = OperationResult::SUCCESS;
                response.esp_error = ESP_OK;
            }

            // Send response back (only for synchronous requests)
            if (msg.request_id != 0) {
                // Use shorter timeout and non-blocking send to prevent deadlock
                if (xQueueSend(response_queue_, &response, pdMS_TO_TICKS(200)) != pdTRUE) {
                    LOG_ERRORF(TAG, "Failed to send response for request ID %u (queue timeout)", msg.request_id);
                }
            }
        }
    }
}

// --- FILE_STATS ---
bool FilesystemTaskDelegate::processFileStatsMessage(const DelegationMessage& msg,
                                                     DelegationResponse& resp) {
    struct stat st {};
    if (stat(msg.file_path, &st) == 0) {
        resp.file_exists = true;
        resp.file_size   = static_cast<size_t>(st.st_size);
        return true;
    }
    resp.file_exists = false;
    resp.file_size   = 0;
    // Not a “serious” error: the file is simply not present.
    resp.esp_error   = ESP_ERR_NOT_FOUND;
    return false;
}

// --- STREAM_FILE ---
bool FilesystemTaskDelegate::processStreamFileMessage(const DelegationMessage& msg,
                                                      DelegationResponse& resp) {
    // Open file in the delegate task (DRAM stack)
    FILE* f = fopen(msg.file_path, "rb");
    if (!f) {
        snprintf(resp.error_message, sizeof(resp.error_message),
                 "open failed: %s", strerror(errno));
        resp.esp_error = ESP_FAIL;
        return false;
    }

    // Stream start ACK
    resp.esp_error = ESP_OK;
    // (the response will be sent by the main loop, as for the other ops)

    // Streaming loop: produce-chunk → caller queue
    FilesystemTaskDelegate::StreamChunk chunk{};
    const size_t CH = (msg.stream_chunk_size == 0 || msg.stream_chunk_size > STREAM_CHUNK_MAX)
                      ? STREAM_CHUNK_MAX : msg.stream_chunk_size;

    while (true) {
        size_t n = fread(chunk.data, 1, CH, f);
        if (n > 0) {
            chunk.len = n;
            chunk.status = 0;
            chunk.eof = false;
            if (xQueueSend(msg.stream_queue, &chunk, portMAX_DELAY) != pdTRUE) {
                // The consumer no longer receives: we stop
                fclose(f);
                return false;
            }
        }
        if (n < CH) {
            // EOF or error
            if (feof(f)) {
                chunk.len = 0;
                chunk.status = 0;
                chunk.eof = true;
            } else {
                chunk.len = 0;
                chunk.status = -1; // read error
                chunk.eof = true;
            }
            // We try to signal the end to the consumer
            (void)xQueueSend(msg.stream_queue, &chunk, pdMS_TO_TICKS(500));
            fclose(f);
            break;
        }
    }
    return true;
}

bool FilesystemTaskDelegate::processPSRAMStreamMessage(const DelegationMessage& msg,
                                                       DelegationResponse& resp) {
    // Hybrid PSRAM-backed streaming implementation
    // Producer (this task with DRAM stack) reads via staging buffer to PSRAM ring
    // Consumer (webserver with PSRAM stack) receives descriptors and reads from PSRAM

    LOG_INFOF(TAG, "Starting PSRAM stream processing for file: %s", msg.file_path);

    // CRITICAL: Check DRAM before fopen() - newlib needs memory for FILE lock structures
    // newlib's fopen() allocates locks internally via malloc(), which REQUIRES DRAM
    // The lock_init_generic() call will abort() if malloc() fails
    size_t free_dram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    const size_t MIN_DRAM_FOR_FOPEN = 20480; // Need at least 20KB total DRAM (increased from 12KB)
    const size_t MIN_LARGEST_BLOCK = 16384;  // Need at least 16KB contiguous block (increased from 8KB)

    if (free_dram < MIN_DRAM_FOR_FOPEN || largest_block < MIN_LARGEST_BLOCK) {
        LOG_ERRORF(TAG, "❌ Insufficient DRAM for fopen(): free=%u bytes (need %u), largest=%u (need %u) - aborting stream to prevent crash",
                  (unsigned)free_dram, (unsigned)MIN_DRAM_FOR_FOPEN,
                  (unsigned)largest_block, (unsigned)MIN_LARGEST_BLOCK);
        LOG_WARNING(TAG, "System is running low on internal RAM - cannot open file safely");
        // Release streaming semaphore
        xSemaphoreGive(streaming_semaphore_);
        return false;
    }

    // Open file with DRAM stack (safe)
    LOG_INFOF(TAG, "Attempting to open file: %s (DRAM: %u bytes, largest: %u bytes)",
             msg.file_path, (unsigned)free_dram, (unsigned)largest_block);
    FILE* f = fopen(msg.file_path, "rb");
    bool file_exists = (f != nullptr);

    if (!f) {
        LOG_WARNINGF(TAG, "File %s does not exist (%s) - treating as empty file", msg.file_path, strerror(errno));
    } else {
        LOG_INFOF(TAG, "File opened successfully: %s", msg.file_path);
    }

    LOG_DEBUG(TAG, "PSRAM streaming started");

    // ACK successful start
    resp.esp_error = ESP_OK;
    resp.result = OperationResult::SUCCESS;

    // Check file size first - handle empty/nonexistent files immediately
    long file_size = 0;
    if (file_exists) {
        fseek(f, 0, SEEK_END);
        file_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        LOG_INFOF(TAG, "File size check: %ld bytes for file %s", file_size, msg.file_path);
    } else {
        LOG_INFOF(TAG, "File does not exist, treating as 0 bytes: %s", msg.file_path);
    }

    if (file_size == 0) {
        LOG_INFO(TAG, "Empty file detected - sending immediate EOF");

        // For empty files, immediately send EOF descriptor
        bool eof_sent = false;
        uint32_t attempts = 0;

        while (!eof_sent && attempts < 10) {  // Max 10 attempts to find empty slot
            if (xSemaphoreTake(ring_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
                for (uint32_t i = 0; i < CIRCULAR_QUEUE_SIZE && !eof_sent; i++) {
                    uint32_t slot_index = (producer_index_ + i) % CIRCULAR_QUEUE_SIZE;
                    RingDescriptor* slot = &circular_descriptors_[slot_index];

                    if (slot->state == SlotState::EMPTY) {
                        // Send EOF immediately for empty file
                        slot->offset = 0;
                        slot->length = 0;
                        slot->eof = true;
                        slot->sequence = sequence_counter_;
                        sequence_counter_ = sequence_counter_ + 1;
                        slot->state = SlotState::READY;

                        producer_index_ = (slot_index + 1) % CIRCULAR_QUEUE_SIZE;
                        eof_sent = true;

                        LOG_INFO(TAG, "Empty file EOF sent immediately");
                        break;
                    }
                }
                xSemaphoreGive(ring_mutex_);
            }

            if (!eof_sent) {
                vTaskDelay(pdMS_TO_TICKS(1)); // Brief delay before retry
                attempts++;
            }
        }

        if (file_exists) {
            fclose(f);
        }
        if (eof_sent) {
            LOG_INFO(TAG, "PSRAM streaming completed (empty file)");
        } else {
            LOG_ERROR(TAG, "Failed to send EOF for empty file");
        }

        // Release streaming semaphore
        xSemaphoreGive(streaming_semaphore_);
        return eof_sent;
    }

    // Handle tail functionality for non-empty files
    if (msg.tail_lines > 0) {
        LOG_INFOF(TAG, "Tail mode: finding last %d lines in %ld byte file", msg.tail_lines, file_size);

        // Scan backwards to find newlines
        long pos = file_size - 1;
        int lines_found = 0;

        while (pos >= 0 && lines_found < msg.tail_lines) {
            fseek(f, pos, SEEK_SET);
            char c = fgetc(f);
            if (c == '\n') {
                lines_found++;
            }
            pos--;
        }

        // Position after the last newline we found (or at start if not enough lines)
        if (lines_found == msg.tail_lines && pos >= 0) {
            fseek(f, pos + 2, SEEK_SET); // +2 to skip the newline we found
        } else {
            fseek(f, 0, SEEK_SET); // Start from beginning if not enough lines
        }

        LOG_INFOF(TAG, "Tail positioned at offset %ld (found %d lines)", ftell(f), lines_found);
    } else {
        // Read entire file (default behavior)
        fseek(f, 0, SEEK_SET);
    }

    // Give consumer time to start processing - crucial for parallelization
    vTaskDelay(pdMS_TO_TICKS(10)); // 10ms delay to let consumer get ready
    LOG_DEBUG(TAG, "Producer starting file reading loop");

    // Hybrid streaming loop - producer side
    bool stream_completed = false;

    while (!stream_completed) {
        // Read into DRAM staging buffer (safe during cache disable)
        size_t bytes_read = fread(dram_staging_buffer_, 1, DRAM_STAGING_SIZE, f);

        if (bytes_read > 0) {
            // Wait for space in PSRAM ring buffer with improved synchronization
            xSemaphoreTake(ring_mutex_, portMAX_DELAY);

            // Calculate free space, ensuring we don't overwrite unconsumed data
            size_t used_bytes = (ring_head_ >= ring_tail_) ?
                (ring_head_ - ring_tail_) :
                (PSRAM_RING_SIZE - ring_tail_ + ring_head_);
            size_t free_bytes = PSRAM_RING_SIZE - used_bytes - 1; // Leave 1 byte margin

            // Enhanced backpressure with timeout
            uint32_t backpressure_count = 0;
            while (free_bytes < bytes_read && backpressure_count < 100) { // Max 500ms wait
                xSemaphoreGive(ring_mutex_);
                vTaskDelay(pdMS_TO_TICKS(5));
                xSemaphoreTake(ring_mutex_, portMAX_DELAY);

                // Recalculate space
                used_bytes = (ring_head_ >= ring_tail_) ?
                    (ring_head_ - ring_tail_) :
                    (PSRAM_RING_SIZE - ring_tail_ + ring_head_);
                free_bytes = PSRAM_RING_SIZE - used_bytes - 1;
                backpressure_count++;
            }

            // If still no space, consumer is really stuck
            if (free_bytes < bytes_read) {
                LOG_ERROR(TAG, "PSRAM ring buffer full - consumer blocked");
                xSemaphoreGive(ring_mutex_);
                fclose(f);
                // Release streaming semaphore on error
                xSemaphoreGive(streaming_semaphore_);
                return false;
            }

            // Copy from DRAM staging to PSRAM ring (cache enabled now)
            uint32_t offset = ring_head_;
            uint32_t first_chunk = std::min((size_t)bytes_read, (size_t)(PSRAM_RING_SIZE - offset));
            memcpy(&psram_ring_buffer_[offset], dram_staging_buffer_, first_chunk);

            if (bytes_read > first_chunk) {
                // Handle wrap-around
                memcpy(&psram_ring_buffer_[0], dram_staging_buffer_ + first_chunk, bytes_read - first_chunk);
            }

            ring_head_ = (ring_head_ + bytes_read) % PSRAM_RING_SIZE;
            xSemaphoreGive(ring_mutex_);

            // Find next available slot in circular queue
            bool slot_found = false;
            TickType_t start_time = xTaskGetTickCount();

            while (!slot_found && (xTaskGetTickCount() - start_time) < msg.timeout_ticks) {  // Wait until timeout
                // Try all slots starting from current producer index
                for (uint32_t attempts = 0; attempts < CIRCULAR_QUEUE_SIZE && !slot_found; attempts++) {
                    uint32_t test_index = (producer_index_ + attempts) % CIRCULAR_QUEUE_SIZE;
                    RingDescriptor* producer_slot = &circular_descriptors_[test_index];

                    if (producer_slot->state == SlotState::EMPTY) {
                        // Fill the slot
                        producer_slot->offset = offset;
                        producer_slot->length = (uint16_t)bytes_read;
                        // Check if this is the last chunk (EOF condition)
                        producer_slot->eof = (bytes_read < DRAM_STAGING_SIZE);
                        producer_slot->sequence = sequence_counter_;
                        sequence_counter_ = sequence_counter_ + 1;
                        producer_slot->state = SlotState::READY;

                        // Update producer index to next slot
                        producer_index_ = (test_index + 1) % CIRCULAR_QUEUE_SIZE;
                        slot_found = true;
                        //TickType_t elapsed = xTaskGetTickCount() - start_time;
                        //LOG_DEBUGF(TAG, "Producer filled slot %u (attempts: %u, elapsed: %u ms)", test_index, attempts, elapsed * portTICK_PERIOD_MS);
                    }
                }

                if (!slot_found) {
                    // All slots busy, yield briefly to consumer task then wait a bit longer
                    //TickType_t elapsed = xTaskGetTickCount() - start_time;
                    //LOG_DEBUGF(TAG, "Producer waiting for slot (elapsed: %u ms)", elapsed * portTICK_PERIOD_MS);
                    taskYIELD();
                    vTaskDelay(pdMS_TO_TICKS(5)); // 5ms delay to allow consumer to work
                }
            }

            if (!slot_found) {
                // Log diagnostic info about slot states
                TickType_t elapsed = xTaskGetTickCount() - start_time;
                LOG_ERRORF(TAG, "Failed to find available descriptor slot after %u ms - slot states:", elapsed * portTICK_PERIOD_MS);
                for (int i = 0; i < CIRCULAR_QUEUE_SIZE; i++) {
                    LOG_ERRORF(TAG, "  Slot %d: state=%d, seq=%u", i, (int)circular_descriptors_[i].state, circular_descriptors_[i].sequence);
                }
                fclose(f);
                // Release streaming semaphore on error
                xSemaphoreGive(streaming_semaphore_);
                return false;
            }

            //LOG_DEBUG(TAG, "Sent PSRAM chunk");

            // Yield CPU briefly to allow consumer task to process chunks
            // This enables true parallelization instead of batch processing
            taskYIELD();
        }

        // Check for EOF or error
        if (bytes_read < DRAM_STAGING_SIZE) {
            // Send EOF/error descriptor using same logic as data chunks
            bool final_slot_found = false;
            uint32_t final_loops = 0;

            while (!final_slot_found && final_loops < 5) {  // Shorter retry for EOF
                for (uint32_t attempts = 0; attempts < CIRCULAR_QUEUE_SIZE && !final_slot_found; attempts++) {
                    uint32_t test_index = (producer_index_ + attempts) % CIRCULAR_QUEUE_SIZE;
                    RingDescriptor* final_slot = &circular_descriptors_[test_index];

                    if (final_slot->state == SlotState::EMPTY) {
                        // Fill EOF/error descriptor
                        final_slot->offset = 0;
                        final_slot->length = 0;
                        final_slot->eof = true;
                        final_slot->sequence = sequence_counter_;
                        sequence_counter_ = sequence_counter_ + 1;
                        final_slot->state = SlotState::READY;

                        producer_index_ = (test_index + 1) % CIRCULAR_QUEUE_SIZE;
                        final_slot_found = true;

                        if (feof(f)) {
                            LOG_DEBUG(TAG, "EOF descriptor sent");
                        } else {
                            LOG_ERROR(TAG, "File read error descriptor sent");
                        }
                    }
                }

                if (!final_slot_found) {
                    vTaskDelay(pdMS_TO_TICKS(5));
                    final_loops++;
                }
            }

            stream_completed = true;
        }
    }

    fclose(f);
    LOG_INFO(TAG, "PSRAM streaming completed");

    // Release streaming semaphore - allows next streaming request to proceed
    xSemaphoreGive(streaming_semaphore_);
    LOG_DEBUG(TAG, "Released streaming semaphore");

    return true;
}

esp_err_t FilesystemTaskDelegate::startFileStreaming(const std::string& path,
                                                     QueueHandle_t out_q,
                                                     size_t chunk_size,
                                                     uint32_t timeout_ms) {
    DelegationMessage req{};
    req.operation = OperationType::STREAM_FILE;
    snprintf(req.file_path, sizeof(req.file_path), "%s", path.c_str());
    req.request_id = next_request_id_;
    req.timeout_ticks = pdMS_TO_TICKS(timeout_ms);
    req.stream_queue = out_q;
    req.stream_chunk_size = chunk_size;

    DelegationResponse resp{};
    if (!sendRequestAndWait(req, resp, 1000)) {
        return ESP_ERR_TIMEOUT;
    }
    return (resp.esp_error == ESP_OK) ? ESP_OK : resp.esp_error;
}

bool FilesystemTaskDelegate::startPSRAMStreaming(const char* file_path,
                                                 uint32_t timeout_ms,
                                                 int tail_lines) {
    if (!isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready for PSRAM streaming");
        return false;
    }

    const char* safe_path = file_path ? file_path : "(null)";

    // Acquire streaming serialization semaphore - handles concurrent requests
    // This ensures only one PSRAM streaming can be active at a time
    LOG_INFOF(TAG, "Waiting for streaming semaphore (file: %s)...", safe_path);
    if (xSemaphoreTake(streaming_semaphore_, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        LOG_WARNINGF(TAG, "Timeout waiting for streaming semaphore (file: %s, timeout: %ums)", safe_path, timeout_ms);
        return false;
    }
    LOG_INFOF(TAG, "Acquired streaming semaphore for file: %s", safe_path);

    // Reset ring buffer positions and circular queue
    xSemaphoreTake(ring_mutex_, portMAX_DELAY);

    // CRITICAL FIX: Reset everything if buffer is completely empty (head == tail)
    // This prevents stale descriptors from previous streams being consumed
    if (ring_head_ == ring_tail_) {
        ring_head_ = 0;
        ring_tail_ = 0;
        producer_index_ = 0;
        consumer_index_ = 0;

        // Mark all descriptor slots as EMPTY to ensure no stale descriptors remain
        for (int i = 0; i < CIRCULAR_QUEUE_SIZE; i++) {
            circular_descriptors_[i].state = SlotState::EMPTY;
        }

        LOG_DEBUG(TAG, "Ring buffer was empty - full reset: head=0, tail=0, producer=0, consumer=0, all slots cleared");
    }

    LOG_DEBUGF(TAG, "Current ring buffer state: head=%u, tail=%u", ring_head_, ring_tail_);

    // Check available slots
    uint32_t available_slots = 0;
    for (int i = 0; i < CIRCULAR_QUEUE_SIZE; i++) {
        if (circular_descriptors_[i].state == SlotState::EMPTY) {
            available_slots++;
        }
    }

    xSemaphoreGive(ring_mutex_);

    // Ensure we have sufficient slots available for streaming
    if (available_slots < 2) {
        LOG_WARNINGF(TAG, "Low available slots (%u) - waiting for consumer cleanup", available_slots);
        vTaskDelay(pdMS_TO_TICKS(10));  // Brief wait for consumer to free up slots
    }

    LOG_DEBUGF(TAG, "PSRAM streaming request sending, %u slots available", available_slots);

    DelegationMessage req{};
    req.operation = OperationType::PSRAM_STREAM;
    snprintf(req.file_path, sizeof(req.file_path), "%s", safe_path);
    req.request_id = generateRequestId();
    req.timeout_ticks = pdMS_TO_TICKS(timeout_ms);
    req.tail_lines = tail_lines;

    LOG_INFO(TAG, "Starting PSRAM streaming");

    // Send request fire-and-forget style - we don't wait for completion
    LOG_INFOF(TAG, "Sending PSRAM stream request for file: %s", safe_path);
    if (!sendRequest(req, 1000)) {  // Short timeout just to send the message
        LOG_ERROR(TAG, "Failed to send PSRAM streaming request");
        // The producer will never see this request, so it cannot release the
        // serialization token on our behalf.  Leaving it held made every
        // later log download wait until its timeout.
        xSemaphoreGive(streaming_semaphore_);
        return false;
    }
    LOG_INFO(TAG, "PSRAM stream request sent successfully");

    // Wait briefly for the task to confirm it started processing
    vTaskDelay(pdMS_TO_TICKS(100));  // 100ms should be enough for file open confirmation

    LOG_INFO(TAG, "PSRAM streaming started successfully");
    return true;
}

uint8_t* FilesystemTaskDelegate::getPSRAMRingBuffer() const {
    return psram_ring_buffer_;
}

FilesystemTaskDelegate::RingDescriptor* FilesystemTaskDelegate::getNextDescriptor(uint32_t timeout_ms) {
    TickType_t start_time = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start_time) < timeout_ticks) {
        if (xSemaphoreTake(ring_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
            // Look for any READY descriptor in the circular queue
            for (int i = 0; i < CIRCULAR_QUEUE_SIZE; i++) {
                uint32_t check_index = (consumer_index_ + i) % CIRCULAR_QUEUE_SIZE;
                RingDescriptor* desc = &circular_descriptors_[check_index];

                if (desc->state == SlotState::READY) {
                    // Update consumer index to this found descriptor
                    consumer_index_ = check_index;
                    xSemaphoreGive(ring_mutex_);
                    return desc;
                }
            }
            xSemaphoreGive(ring_mutex_);
        }

        // Brief delay before checking again
        vTaskDelay(pdMS_TO_TICKS(5));  // Reduced delay for better responsiveness
    }

    return nullptr; // Timeout
}

void FilesystemTaskDelegate::markDescriptorConsumed(RingDescriptor* desc) {
    if (!desc) return;

    if (xSemaphoreTake(ring_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
        // Find which slot this descriptor is
        //uint32_t slot_index = (desc - circular_descriptors_);

        // CRITICAL: Advance PSRAM ring buffer tail pointer to free space
        // This enables the producer's backpressure logic to work correctly for large files
        if (desc->length > 0) {  // Only advance for data chunks, not EOF markers
            ring_tail_ = (ring_tail_ + desc->length) % PSRAM_RING_SIZE;
            //LOG_DEBUGF(TAG, "Consumer advanced PSRAM tail to %u (freed %u bytes)", ring_tail_, desc->length);
        }

        // Mark slot as EMPTY for immediate reuse by producer
        desc->state = SlotState::EMPTY;
        //LOG_DEBUGF(TAG, "Consumer marked slot %u as EMPTY (seq: %u)", slot_index, desc->sequence);

        // Advance consumer index to next slot for sequential access
        if (desc == &circular_descriptors_[consumer_index_]) {
            consumer_index_ = (consumer_index_ + 1) % CIRCULAR_QUEUE_SIZE;
            //LOG_DEBUGF(TAG, "Consumer advanced to index %u", consumer_index_);
        }

        xSemaphoreGive(ring_mutex_);
    }
}

bool FilesystemTaskDelegate::sendRequestAndWait(const DelegationMessage& msg,
                                                DelegationResponse& response,
                                                uint32_t timeout_ms) {
    if (!sendRequest(msg, timeout_ms)) {
        return false;
    }
    return waitForResponse(msg.request_id, response, timeout_ms);
}


bool FilesystemTaskDelegate::processRotationMessage(const DelegationMessage& msg, DelegationResponse& response) {
    const char* file_path = msg.file_path;

    ////log_deBUGF(TAG, "rotate start path=%s threshold=%u max=%u", file_path, (unsigned)msg.rotate_bytes, (unsigned)msg.max_files);

    struct stat st{};
    if (stat(file_path, &st) != 0) {
        //log_deBUGF(TAG, "rotate skip path=%s stat_errno=%d", file_path, errno);
        return true;
    }

    ////log_deBUGF(TAG, "rotate inspect path=%s size=%ld threshold=%u", file_path, (long)st.st_size, (unsigned)msg.rotate_bytes);

    if (st.st_size < (off_t)msg.rotate_bytes) {
        ////log_deBUGF(TAG, "rotate skip path=%s size=%ld threshold=%u", file_path, (long)st.st_size, (unsigned)msg.rotate_bytes);
        return true;
    }

    // Perform rotation: file.log -> file.log.1 -> file.log.2 -> ... -> file.log.N
    // Shift existing rotated files
    for (int i = (int)msg.max_files - 1; i >= 1; i--) {
        char old_path[320], new_path[320];
        snprintf(old_path, sizeof(old_path), "%s.%d", file_path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", file_path, i + 1);

        // Remove target if it exists (beyond max_files)
        if (i == (int)msg.max_files - 1) {
            unlink(new_path);
        }

        // Rename old to new (ignore errors if old doesn't exist)
        rename(old_path, new_path);
    }

    // Move current file to .1
    char rotated_path[320];
    snprintf(rotated_path, sizeof(rotated_path), "%s.1", file_path);

    if (rename(file_path, rotated_path) != 0) {
        int rename_err = errno;
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to rename file to backup");
        LOG_ERRORF(TAG, "rotate fail path=%s->%s errno=%d", file_path, rotated_path, rename_err);
        return false;
    }

    //LOG_INFOF(TAG, "rotate done path=%s backup=%s", file_path, rotated_path);
    return true;
}

bool FilesystemTaskDelegate::processDirectoryMessage(const DelegationMessage& msg, DelegationResponse& response) {
    auto ensure_directory = [&](const std::string& path) -> bool {
        if (path.empty()) {
            return true;
        }

        esp_err_t result = AsyncStorage::Global::createDir(path);
        if (result == ESP_OK) {
            return true;
        }

        if (result == ESP_ERR_INVALID_STATE || result == ESP_FAIL) {
            struct stat st {};
            if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                return true;
            }
        }

        response.esp_error = result;
        snprintf(response.error_message, sizeof(response.error_message),
                 "Failed to create directory '%s': %s",
                 path.c_str(), esp_err_to_name(result));
        return false;
    };

    std::string target = msg.file_path;
    if (target.empty()) {
        response.esp_error = ESP_OK;
        return true;
    }

    std::string partial;
    partial.reserve(target.size());

    for (size_t i = 0; i < target.size(); ++i) {
        char c = target[i];
        partial.push_back(c);

        bool boundary = (c == '/') || (i == target.size() - 1);
        if (!boundary) {
            continue;
        }

        if (partial.size() == 1 && partial[0] == '/') {
            continue;
        }

        std::string to_create = partial;
        if (!to_create.empty() && to_create.back() == '/' && i != target.size() - 1) {
            to_create.pop_back();
        }

        if (!ensure_directory(to_create)) {
            return false;
        }
    }

    response.esp_error = ESP_OK;
    return true;
}

bool FilesystemTaskDelegate::processDeleteMessage(const DelegationMessage& msg, DelegationResponse& response) {
    if (unlink(msg.file_path) != 0) {
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to delete file: %s", strerror(errno));
        return false;
    }

    //LOG_INFOF(TAG, "✅ File deleted: %s", msg.file_path);
    return true;
}

bool FilesystemTaskDelegate::processListFilesMessage(const DelegationMessage& msg, DelegationResponse& response) {
    //LOG_INFOF(TAG, "Listing files in directory: %s", msg.file_path);

    response.file_count = 0;
    memset(response.file_list, 0, sizeof(response.file_list));

    DIR* d = opendir(msg.file_path);
    if (!d) {
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to open directory");
        return false;
    }

    size_t buffer_pos = 0;
    uint32_t file_count = 0;
    struct dirent* e;

    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;  // Skip . and ..
        }

        // Check if it's a regular file
        std::string full_path = std::string(msg.file_path) + "/" + e->d_name;
        struct stat st{};
        if (stat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            // Add filename to buffer if there's space
            size_t name_len = strlen(e->d_name);
            if (buffer_pos + name_len + 2 < sizeof(response.file_list)) {  // +2 for '\n' and '\0'
                strcpy(response.file_list + buffer_pos, e->d_name);
                buffer_pos += name_len;
                response.file_list[buffer_pos++] = '\n';  // Use newline as separator
                file_count++;
            } else {
                LOG_WARNINGF(TAG, "Buffer full, truncating file list at %u files", file_count);
                break;
            }
        }
    }

    closedir(d);
    response.file_count = file_count;

    //LOG_INFOF(TAG, "✅ Listed %u files from directory: %s", file_count, msg.file_path);
    return true;
}

bool FilesystemTaskDelegate::processCleanupOrphansMessage(const DelegationMessage& msg, DelegationResponse& response) {
    //LOG_INFOF(TAG, "Cleaning up orphan files in directory: %s (age threshold: %llu ms)", msg.file_path, msg.age_threshold_ms);

    DIR* d = opendir(msg.file_path);
    if (!d) {
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to open directory");
        return false;
    }

    uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    uint32_t deleted_count = 0;
    struct dirent* e;

    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;  // Skip . and ..
        }

        std::string full_path = std::string(msg.file_path) + "/" + e->d_name;
        struct stat st{};
        if (stat(full_path.c_str(), &st) == 0) {
            uint64_t file_age_ms = (now_ms - (st.st_mtime * 1000ULL));

            if (file_age_ms > msg.age_threshold_ms) {
                if (unlink(full_path.c_str()) == 0) {
                    deleted_count++;
            //LOG_INFOF(TAG, "Deleted orphan file: %s (age: %llu ms)", full_path.c_str(), file_age_ms);
                } else {
                    LOG_WARNINGF(TAG, "Failed to delete orphan file: %s", full_path.c_str());
                }
            }
        }
    }

    closedir(d);

    //LOG_INFOF(TAG, "✅ Cleanup completed: deleted %u orphan files from %s", deleted_count, msg.file_path);

    response.file_count = deleted_count;  // Reuse file_count field for deleted count
    return true;
}

bool FilesystemTaskDelegate::processTrimFileMessage(const DelegationMessage& msg, DelegationResponse& response) {
    const char* file_path = msg.file_path;
    size_t max_size_bytes = msg.rotate_bytes; // Reuse rotate_bytes field for max_size

    //log_deBUGF(TAG, "Trimming file %s to max size %zu bytes", file_path, max_size_bytes);

    // Check if file exists and get current size
    struct stat st{};
    if (stat(file_path, &st) != 0) {
        //log_deBUGF(TAG, "File does not exist: %s", file_path);
        return true; // File doesn't exist, nothing to trim
    }

    size_t current_size = (size_t)st.st_size;
    if (current_size <= max_size_bytes) {
        //log_deBUGF(TAG, "File %s size %zu is within limit %zu", file_path, current_size, max_size_bytes);
        return true; // File is within size limit
    }

    // File needs trimming - keep the newest data (end of file)
    FILE* file = fopen(file_path, "r+b");
    if (!file) {
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to open file for trimming");
        LOG_ERRORF(TAG, "Failed to open file for trimming: %s", file_path);
        return false;
    }

    // Calculate how much data to keep (newest data from end of file)
    size_t bytes_to_remove = current_size - max_size_bytes;

    // Create a temp file to avoid memory issues with large files
    std::string temp_path = std::string(file_path) + ".trim_tmp";
    FILE* temp_file = fopen(temp_path.c_str(), "wb");
    if (!temp_file) {
        fclose(file);
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to create temp file for trimming");
        LOG_ERRORF(TAG, "Failed to create temp file: %s", temp_path.c_str());
        return false;
    }

    // Seek to the position where we want to start copying (skip old data)
    if (fseek(file, bytes_to_remove, SEEK_SET) != 0) {
        fclose(file);
        fclose(temp_file);
        unlink(temp_path.c_str());
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to seek in file");
        LOG_ERRORF(TAG, "Failed to seek to position %zu in file %s", bytes_to_remove, file_path);
        return false;
    }

    // Copy data from original file to temp file in chunks to avoid memory issues
    const size_t CHUNK_SIZE = 8192; // 8KB chunks
    char buffer[CHUNK_SIZE];
    size_t bytes_copied = 0;

    while (bytes_copied < max_size_bytes) {
        size_t to_read = std::min(CHUNK_SIZE, max_size_bytes - bytes_copied);
        size_t bytes_read = fread(buffer, 1, to_read, file);

        if (bytes_read == 0) {
            if (feof(file)) {
                break; // End of file reached
            } else {
                // Read error
                fclose(file);
                fclose(temp_file);
                unlink(temp_path.c_str());
                snprintf(response.error_message, sizeof(response.error_message),
                        "Error reading from file");
                LOG_ERRORF(TAG, "Error reading from file %s", file_path);
                return false;
            }
        }

        size_t bytes_written = fwrite(buffer, 1, bytes_read, temp_file);
        if (bytes_written != bytes_read) {
            fclose(file);
            fclose(temp_file);
            unlink(temp_path.c_str());
            snprintf(response.error_message, sizeof(response.error_message),
                    "Error writing to temp file");
            LOG_ERRORF(TAG, "Error writing to temp file %s", temp_path.c_str());
            return false;
        }

        bytes_copied += bytes_read;
    }

    fclose(file);
    fflush(temp_file);
    fsync(fileno(temp_file));
    fclose(temp_file);

    // Replace original file with trimmed version
    if (rename(temp_path.c_str(), file_path) != 0) {
        unlink(temp_path.c_str());
        snprintf(response.error_message, sizeof(response.error_message),
                "Failed to replace original file");
        LOG_ERRORF(TAG, "Failed to replace original file %s with trimmed version", file_path);
        return false;
    }

    LOG_INFOF(TAG, "Successfully trimmed file %s from %zu to %zu bytes (removed %zu bytes)",
              file_path, current_size, bytes_copied, bytes_to_remove);
    return true;
}

bool FilesystemTaskDelegate::rotateFileAsync(const std::string& file_path,
                        size_t rotate_bytes,
                        uint32_t max_files) {
    if (!isReady()) {
        LOG_WARNING(TAG, "rotateFileAsync called while delegate not ready");
        return false;
    }

    DelegationMessage msg{};
    msg.operation = OperationType::FILE_ROTATION;
    strncpy(msg.file_path, file_path.c_str(), sizeof(msg.file_path) - 1);
    msg.rotate_bytes = rotate_bytes;
    msg.max_files = max_files;
    msg.request_id = 0;
    msg.timeout_ticks = 0;

    // Debug logging disabled for compilation
    // UBaseType_t pending = request_queue_ ? uxQueueMessagesWaiting(request_queue_) : 0;
    ////log_deBUGF(TAG, "rotate enqueue async path=%s size=%u max=%u pending=%u", file_path.c_str(), (unsigned)rotate_bytes, (unsigned)max_files, (unsigned)pending);

    if (xQueueSend(request_queue_, &msg, 0) != pdTRUE) {
        LOG_WARNINGF(TAG, "rotateFileAsync queue full for %s", file_path.c_str());
        return false;
    }

    ////log_deBUGF(TAG, "rotate queued async path=%s", file_path.c_str());
    return true;
}

FilesystemTaskDelegate::OperationResult FilesystemTaskDelegate::rotateFileSync(
    const std::string& file_path, size_t rotate_bytes, uint32_t max_files, uint32_t timeout_ms) {

    if (!isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready");
        return OperationResult::FAILURE;
    }

    DelegationMessage msg{};
    msg.operation = OperationType::FILE_ROTATION;
    strncpy(msg.file_path, file_path.c_str(), sizeof(msg.file_path) - 1);
    msg.rotate_bytes = rotate_bytes;
    msg.max_files = max_files;
    msg.request_id = generateRequestId();
    msg.timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    if (!sendRequest(msg, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    DelegationResponse response;
    if (!waitForResponse(msg.request_id, response, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    return response.result;
}

FilesystemTaskDelegate::OperationResult FilesystemTaskDelegate::createDirectorySync(
    const std::string& dir_path, uint32_t timeout_ms) {

    if (!isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready");
        return OperationResult::FAILURE;
    }

    DelegationMessage msg{};
    msg.operation = OperationType::DIRECTORY_CREATE;
    strncpy(msg.file_path, dir_path.c_str(), sizeof(msg.file_path) - 1);
    msg.request_id = generateRequestId();
    msg.timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    if (!sendRequest(msg, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    DelegationResponse response;
    if (!waitForResponse(msg.request_id, response, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    return response.result;
}

bool FilesystemTaskDelegate::sendRequest(const DelegationMessage& msg, uint32_t timeout_ms) {
    // Check queue space before sending to prevent overflow
    UBaseType_t pending = uxQueueMessagesWaiting(request_queue_);
    if (pending >= (REQUEST_QUEUE_SIZE - 2)) {  // Trigger flush at 8/10 instead of 9/10
        LOG_WARNINGF(TAG, "Request queue nearly full (%u/%u), flushing stale requests",
                    (unsigned)pending, (unsigned)REQUEST_QUEUE_SIZE);

        // Emergency flush: remove old messages to make space
        DelegationMessage stale_msg;
        size_t flushed_count = 0;
        while (uxQueueMessagesWaiting(request_queue_) > (REQUEST_QUEUE_SIZE / 2) && flushed_count < 5) {
            if (xQueueReceive(request_queue_, &stale_msg, 0) == pdTRUE) {
                LOG_DEBUGF(TAG, "Flushed stale request type %d", (int)stale_msg.operation);
                flushed_count++;
            } else {
                break;
            }
        }
        LOG_INFOF(TAG, "Queue flushed %u requests, pending: %u/%u",
                 (unsigned)flushed_count, (unsigned)uxQueueMessagesWaiting(request_queue_), (unsigned)REQUEST_QUEUE_SIZE);
    }

    // Use non-blocking send with shorter timeout to prevent stack corruption
    TickType_t send_timeout = pdMS_TO_TICKS(std::min<uint32_t>(timeout_ms, 500u));
    return xQueueSend(request_queue_, &msg, send_timeout) == pdTRUE;
}

bool FilesystemTaskDelegate::waitForResponse(uint32_t request_id, DelegationResponse& response, uint32_t timeout_ms) {
    TickType_t start_time = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    // Initialize response to prevent stack corruption from uninitialized data
    memset(&response, 0, sizeof(response));

    while ((xTaskGetTickCount() - start_time) < timeout_ticks) {
        DelegationResponse temp_response;
        memset(&temp_response, 0, sizeof(temp_response));

        if (xQueueReceive(response_queue_, &temp_response, pdMS_TO_TICKS(100)) == pdTRUE) {
            if (temp_response.request_id == request_id) {
                // Safe copy to prevent stack corruption
                memcpy(&response, &temp_response, sizeof(response));
                return true;
            }
            // Wrong response, put it back safely
            if (xQueueSendToFront(response_queue_, &temp_response, 0) != pdTRUE) {
                LOG_WARNING(TAG, "Failed to return mismatched response to queue");
            }
        }
    }

    return false;
}

FilesystemTaskDelegate::OperationResult FilesystemTaskDelegate::listFilesSync(
    const std::string& dir_path, std::vector<std::string>& file_list, uint32_t timeout_ms) {

    if (!isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready");
        return OperationResult::FAILURE;
    }

    file_list.clear();

    DelegationMessage msg{};
    msg.operation = OperationType::LIST_FILES;
    strncpy(msg.file_path, dir_path.c_str(), sizeof(msg.file_path) - 1);
    msg.request_id = generateRequestId();
    msg.timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    if (!sendRequest(msg, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    DelegationResponse response;
    if (!waitForResponse(msg.request_id, response, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    if (response.result == OperationResult::SUCCESS) {
        // Parse newline-separated file list
        char* token = strtok(response.file_list, "\n");
        while (token != nullptr) {
            file_list.push_back(std::string(token));
            token = strtok(nullptr, "\n");
        }
        //LOG_INFOF(TAG, "Successfully retrieved %u files from delegate", (unsigned)file_list.size());
    }

    return response.result;
}

FilesystemTaskDelegate::OperationResult FilesystemTaskDelegate::cleanupOrphanFilesSync(
    const std::string& dir_path, uint64_t age_threshold_ms, uint32_t timeout_ms) {

    if (!isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready");
        return OperationResult::FAILURE;
    }

    DelegationMessage msg{};
    msg.operation = OperationType::CLEANUP_ORPHANS;
    strncpy(msg.file_path, dir_path.c_str(), sizeof(msg.file_path) - 1);
    msg.age_threshold_ms = age_threshold_ms;
    msg.request_id = generateRequestId();
    msg.timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    if (!sendRequest(msg, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    DelegationResponse response;
    if (!waitForResponse(msg.request_id, response, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    return response.result;
}

FilesystemTaskDelegate::OperationResult FilesystemTaskDelegate::trimFileSync(
    const std::string& file_path, size_t max_size_bytes, uint32_t timeout_ms) {

    if (!isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready");
        return OperationResult::FAILURE;
    }

    DelegationMessage msg{};
    msg.operation = OperationType::FILE_TRIM;
    strncpy(msg.file_path, file_path.c_str(), sizeof(msg.file_path) - 1);
    msg.rotate_bytes = max_size_bytes; // Reuse rotate_bytes field for max_size
    msg.request_id = generateRequestId();
    msg.timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    if (!sendRequest(msg, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    DelegationResponse response;
    if (!waitForResponse(msg.request_id, response, timeout_ms)) {
        return OperationResult::TIMEOUT;
    }

    return response.result;
}

bool FilesystemTaskDelegate::trimFileAsync(const std::string& file_path, size_t max_size_bytes) {
    if (!isReady()) {
        LOG_WARNING(TAG, "trimFileAsync called while delegate not ready");
        return false;
    }

    DelegationMessage msg{};
    msg.operation = OperationType::FILE_TRIM;
    strncpy(msg.file_path, file_path.c_str(), sizeof(msg.file_path) - 1);
    msg.rotate_bytes = max_size_bytes; // Reuse rotate_bytes field for max_size
    msg.request_id = 0; // Async operations don't need response
    msg.timeout_ticks = 0;

    ////log_deBUGF(TAG, "trim enqueue async path=%s max_size=%zu", file_path.c_str(), max_size_bytes);

    if (xQueueSend(request_queue_, &msg, 0) != pdTRUE) {
        LOG_WARNINGF(TAG, "trimFileAsync queue full for %s", file_path.c_str());
        return false;
    }

    ////log_deBUGF(TAG, "trim queued async path=%s", file_path.c_str());
    return true;
}

uint32_t FilesystemTaskDelegate::generateRequestId() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return next_request_id_++;
}

uint32_t FilesystemTaskDelegate::getPendingOperations() const {
    if (!request_queue_) return 0;
    return uxQueueMessagesWaiting(request_queue_);
}

// File I/O operations implementation

bool FilesystemTaskDelegate::readFileSync(const std::string& file_path, psram_string& content, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (!initialized_) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not properly initialized");
        return false;
    }

    // FILE_READ used to ask the delegate worker (which has an internal-RAM
    // stack) to construct a psram_string.  That operation was intentionally
    // disabled and consequently made every non-empty persistent file fail.
    // AsyncStorage owns the safe flash-I/O worker and returns the completed
    // value to this caller after cache-sensitive I/O has finished.
    const esp_err_t result = AsyncStorage::Global::readFile(file_path, content);
    if (result != ESP_OK) {
        LOG_WARNINGF(TAG, "File read failed for %s: %s", file_path.c_str(), esp_err_to_name(result));
        return false;
    }
    return true;
}

bool FilesystemTaskDelegate::writeFileSync(const std::string& file_path, const psram_string& content, uint32_t timeout_ms) {
    if (!initialized_ || !fileio_request_queue_ || !fileio_response_queue_) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not properly initialized");
        return false;
    }

    FileIORequest request = {};
    request.request_id = generateRequestId();
    request.operation = OperationType::FILE_WRITE;
    strncpy(request.file_path, file_path.c_str(), sizeof(request.file_path) - 1);
    request.psram_data = const_cast<psram_string*>(&content);
    request.callback = nullptr;
    request.timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    // Debug: Sending file write request

    if (xQueueSend(fileio_request_queue_, &request, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERRORF(TAG, "Failed to queue file write request for %s", file_path.c_str());
        return false;
    }

    // Wait for response
    TickType_t start_ticks = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start_ticks) < timeout_ticks) {
        FileIOResponse* response = nullptr;
        if (xQueueReceive(fileio_response_queue_, &response, pdMS_TO_TICKS(100)) == pdTRUE && response) {
            if (response->request_id == request.request_id) {
                if (response->result == OperationResult::SUCCESS) {
                    delete response;
                    return true;
                } else {
                    LOG_ERRORF(TAG, "File write failed id=%u result=%d", response->request_id, static_cast<int>(response->result));
                    delete response;
                    return false;
                }
            }
            delete response;
        }
    }

    LOG_ERRORF(TAG, "File write timeout for %s", file_path.c_str());
    return false;
}

bool FilesystemTaskDelegate::writeFileAsync(const std::string& file_path, const psram_string& content,
                                           std::function<void(bool)> callback) {
    if (!initialized_ || !fileio_request_queue_) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not properly initialized");
        if (callback) callback(false);
        return false;
    }

    uint32_t request_id = generateRequestId();

    // Store callback
    {
        std::lock_guard<std::mutex> lock(fileio_mutex_);
        async_callbacks_[request_id] = callback;
    }

    FileIORequest request = {};
    request.request_id = request_id;
    request.operation = OperationType::FILE_WRITE;
    strncpy(request.file_path, file_path.c_str(), sizeof(request.file_path) - 1);
    request.psram_data = const_cast<psram_string*>(&content);
    request.callback = &callback;
    request.timeout_ticks = pdMS_TO_TICKS(5000); // Default timeout for async

    // Debug: Sending async file write request

    if (xQueueSend(fileio_request_queue_, &request, 0) != pdTRUE) {
        LOG_ERRORF(TAG, "Failed to queue async file write request for %s", file_path.c_str());

        // Remove callback and call it with failure
        {
            std::lock_guard<std::mutex> lock(fileio_mutex_);
            async_callbacks_.erase(request_id);
        }
        if (callback) callback(false);
        return false;
    }

    return true;
}

// File I/O processing implementation

bool FilesystemTaskDelegate::processFileIORequest(const FileIORequest& req, FileIOResponse& response) {
    // Debug: Processing file I/O request

    bool success = false;

    switch (req.operation) {
        case OperationType::FILE_READ:
            success = readFileInternal(req.file_path, response.psram_content);
            break;

        case OperationType::FILE_WRITE:
            if (req.psram_data) {
                success = writeFileInternal(req.file_path, *req.psram_data);
            } else {
                LOG_ERROR(TAG, "FILE_WRITE request missing psram_data");
                success = false;
            }
            break;

        default:
            LOG_ERRORF(TAG, "Unsupported file I/O operation: %s", opTypeToString(req.operation));
            success = false;
            break;
    }

    response.result = success ? OperationResult::SUCCESS : OperationResult::FAILURE;
    response.esp_error = success ? ESP_OK : ESP_FAIL;

    // Debug: File I/O request completed with result

    return success;
}

bool FilesystemTaskDelegate::writeFileInternal(const std::string& file_path, const psram_string& content) {
    //log_deBUGF(TAG, "Writing file %s (size=%zu)", file_path.c_str(), content.size());

    // Create directory if needed
    size_t last_slash = file_path.find_last_of('/');
    if (last_slash != std::string::npos) {
        std::string dir_path = file_path.substr(0, last_slash);
        esp_err_t dir_err = AsyncStorage::Global::createDir(dir_path);
        if (dir_err != ESP_OK && dir_err != ESP_ERR_INVALID_STATE) {
            LOG_ERRORF(TAG, "Failed to create directory: %s (err=%s)",
                       dir_path.c_str(), esp_err_to_name(dir_err));
            return false;
        }
    }

    // Write file atomically (temp + rename)
    std::string temp_path = file_path + ".tmp";

    FILE* f = fopen(temp_path.c_str(), "wb");
    if (!f) {
        LOG_ERRORF(TAG, "Failed to open temp file: %s", temp_path.c_str());
        return false;
    }

    size_t written = fwrite(content.c_str(), 1, content.size(), f);
    bool write_success = (written == content.size());

    if (write_success) {
        fflush(f);
        int fd = fileno(f);
        if (fd >= 0) fsync(fd);
    }

    fclose(f);

    if (!write_success) {
        LOG_ERRORF(TAG, "Failed to write content to temp file: %s", temp_path.c_str());
        unlink(temp_path.c_str());
        return false;
    }

    // Atomic rename
    if (rename(temp_path.c_str(), file_path.c_str()) != 0) {
        LOG_ERRORF(TAG, "Failed to rename temp file %s to %s", temp_path.c_str(), file_path.c_str());
        unlink(temp_path.c_str());
        return false;
    }

    //log_deBUGF(TAG, "Successfully wrote file %s", file_path.c_str());
    return true;
}

bool FilesystemTaskDelegate::readFileInternal(const std::string& file_path, psram_string& content) {
    // Kept only for compatibility with the FILE_READ dispatcher.  New callers
    // use readFileSync(), which delegates to AsyncStorage instead.
    (void)file_path;
    (void)content;
    LOG_WARNING(TAG, "Deprecated FILE_READ request rejected; use readFileSync");
    return false;
}

// ======================= STREAMING FILE ACCESS =======================

bool FilesystemTaskDelegate::openFileForStreaming(const std::string& file_path, void** file_handle) {
    if (!file_handle) {
        LOG_ERROR(TAG, "Invalid file_handle pointer");
        return false;
    }

    FILE* file = fopen(file_path.c_str(), "rb");
    if (!file) {
        //log_deBUGF(TAG, "Failed to open file for streaming: %s", file_path.c_str());
        *file_handle = nullptr;
        return false;
    }

    *file_handle = (void*)file;
    //log_deBUGF(TAG, "Opened file for streaming: %s", file_path.c_str());
    return true;
}

size_t FilesystemTaskDelegate::readStreamChunk(void* file_handle, char* buffer, size_t chunk_size) {
    if (!file_handle || !buffer || chunk_size == 0) {
        return 0;
    }

    FILE* file = (FILE*)file_handle;
    size_t bytes_read = fread(buffer, 1, chunk_size, file);

    // Log only on errors, not on normal EOF
    if (bytes_read == 0 && ferror(file)) {
        //log_deBUG(TAG, "Error reading from stream");
    }

    return bytes_read;
}

void FilesystemTaskDelegate::closeFileStream(void* file_handle) {
    if (!file_handle) {
        return;
    }

    FILE* file = (FILE*)file_handle;
    fclose(file);
    //log_deBUG(TAG, "Closed file stream");
}
