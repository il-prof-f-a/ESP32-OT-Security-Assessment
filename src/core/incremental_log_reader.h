#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <map>
#include <fstream>

struct IncrementalLogEntry {
    std::string timestamp;
    std::string level;
    std::string component;
    std::string message;
    size_t line_number = 0;  // Line number in the file for tracking
};

struct LogReadResult {
    std::vector<IncrementalLogEntry> new_entries;
    size_t last_line_read = 0;
    bool has_more = false;
    std::string error;
};

class IncrementalLogReader {
public:
    IncrementalLogReader();
    ~IncrementalLogReader() = default;

    // Set the log file to monitor
    bool setLogFile(const std::string& file_path);

    // Read new log entries since last read
    LogReadResult readNewEntries(size_t from_line = 0, size_t max_entries = 100);

    // Get latest N log entries (for initial page load)
    LogReadResult getLatestEntries(size_t count = 50);

    // Get total line count
    size_t getTotalLines() const;

    // Check if file has been modified since last check
    bool hasNewData() const;

    // Reset reading position
    void resetPosition();

    // Session management for web clients
    std::string createSession();
    void destroySession(const std::string& session_id);
    LogReadResult readForSession(const std::string& session_id, size_t max_entries = 50);

private:
    std::string log_file_path_;
    mutable std::mutex mutex_;

    // File state tracking
    mutable size_t last_known_size_ = 0;
    mutable time_t last_modified_ = 0;
    mutable size_t total_lines_ = 0;

    // Session tracking for web clients
    struct ClientSession {
        std::string session_id;
        size_t last_line_read = 0;
        time_t created_at = 0;
        time_t last_access = 0;
    };
    std::map<std::string, ClientSession> sessions_;

    // Helper methods
    bool updateFileInfo() const;
    IncrementalLogEntry parseLogLine(const std::string& line, size_t line_number) const;
    std::vector<IncrementalLogEntry> readLinesFromFile(size_t start_line, size_t max_lines) const;
    size_t countLinesInFile() const;
    void cleanupOldSessions();
    std::string generateSessionId() const;
};