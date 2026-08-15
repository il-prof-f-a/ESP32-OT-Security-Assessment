#include "incremental_log_reader.h"
#include "logging_system.h"
#include <sys/stat.h>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <regex>

extern "C" {
    #include "esp_timer.h"
    #include "esp_random.h"
}

static const char* TAG = "IncrementalLogReader";
static const time_t SESSION_TIMEOUT_SEC = 300; // 5 minutes

IncrementalLogReader::IncrementalLogReader() {
    // Initialize
}

bool IncrementalLogReader::setLogFile(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    log_file_path_ = file_path;
    last_known_size_ = 0;
    last_modified_ = 0;
    total_lines_ = 0;

    if (!updateFileInfo()) {
        LOG_ERRORF(TAG, "Failed to set log file: %s", file_path.c_str());
        return false;
    }

    LOG_INFOF(TAG, "Log file set: %s (%zu lines)", file_path.c_str(), total_lines_);
    return true;
}

LogReadResult IncrementalLogReader::readNewEntries(size_t from_line, size_t max_entries) {
    std::lock_guard<std::mutex> lock(mutex_);

    LogReadResult result;

    if (log_file_path_.empty()) {
        result.error = "No log file set";
        return result;
    }

    if (!updateFileInfo()) {
        result.error = "Failed to read file info";
        return result;
    }

    if (from_line >= total_lines_) {
        // No new entries
        result.last_line_read = total_lines_;
        return result;
    }

    // Read new entries
    size_t entries_to_read = std::min(max_entries, total_lines_ - from_line);
    result.new_entries = readLinesFromFile(from_line, entries_to_read);
    result.last_line_read = from_line + result.new_entries.size();
    result.has_more = (result.last_line_read < total_lines_);

    return result;
}

LogReadResult IncrementalLogReader::getLatestEntries(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);

    LogReadResult result;

    if (log_file_path_.empty()) {
        result.error = "No log file set";
        return result;
    }

    if (!updateFileInfo()) {
        result.error = "Failed to read file info";
        return result;
    }

    if (total_lines_ == 0) {
        result.last_line_read = 0;
        return result;
    }

    // Calculate starting line
    size_t start_line = (total_lines_ > count) ? (total_lines_ - count) : 0;
    size_t entries_to_read = total_lines_ - start_line;

    result.new_entries = readLinesFromFile(start_line, entries_to_read);
    result.last_line_read = total_lines_;
    result.has_more = false;

    return result;
}

size_t IncrementalLogReader::getTotalLines() const {
    std::lock_guard<std::mutex> lock(mutex_);
    updateFileInfo();
    return total_lines_;
}

bool IncrementalLogReader::hasNewData() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return updateFileInfo();
}

void IncrementalLogReader::resetPosition() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Reset all sessions
    for (auto& session : sessions_) {
        session.second.last_line_read = 0;
    }
}

std::string IncrementalLogReader::createSession() {
    std::lock_guard<std::mutex> lock(mutex_);

    cleanupOldSessions();

    std::string session_id = generateSessionId();
    ClientSession session;
    session.session_id = session_id;
    session.last_line_read = 0;
    session.created_at = time(nullptr);
    session.last_access = session.created_at;

    sessions_[session_id] = session;

    LOG_INFOF(TAG, "Created session: %s", session_id.c_str());
    return session_id;
}

void IncrementalLogReader::destroySession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        sessions_.erase(it);
        LOG_INFOF(TAG, "Destroyed session: %s", session_id.c_str());
    }
}

LogReadResult IncrementalLogReader::readForSession(const std::string& session_id, size_t max_entries) {
    std::lock_guard<std::mutex> lock(mutex_);

    LogReadResult result;

    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        result.error = "Session not found";
        return result;
    }

    ClientSession& session = it->second;
    session.last_access = time(nullptr);

    if (!updateFileInfo()) {
        result.error = "Failed to read file info";
        return result;
    }

    // Read new entries since last read
    if (session.last_line_read >= total_lines_) {
        result.last_line_read = total_lines_;
        return result; // No new entries
    }

    size_t entries_to_read = std::min(max_entries, total_lines_ - session.last_line_read);
    result.new_entries = readLinesFromFile(session.last_line_read, entries_to_read);

    session.last_line_read += result.new_entries.size();
    result.last_line_read = session.last_line_read;
    result.has_more = (session.last_line_read < total_lines_);

    return result;
}

// Private helper methods
bool IncrementalLogReader::updateFileInfo() const {
    if (log_file_path_.empty()) return false;

    struct stat file_stat;
    if (stat(log_file_path_.c_str(), &file_stat) != 0) {
        return false;
    }

    bool changed = false;

    if (file_stat.st_size != (off_t)last_known_size_ || file_stat.st_mtime != last_modified_) {
        last_known_size_ = file_stat.st_size;
        last_modified_ = file_stat.st_mtime;

        // Recount lines only if file changed
        total_lines_ = countLinesInFile();
        changed = true;
    }

    return changed;
}

IncrementalLogEntry IncrementalLogReader::parseLogLine(const std::string& line, size_t line_number) const {
    IncrementalLogEntry entry;
    entry.line_number = line_number;
    entry.message = line; // Fallback: entire line as message

    // Try to parse standard log format: [TIMESTAMP] LEVEL COMPONENT: MESSAGE
    std::regex log_regex(R"(\[([^\]]+)\]\s+(\w+)\s+([^:]+):\s*(.*))", std::regex_constants::icase);
    std::smatch matches;

    if (std::regex_match(line, matches, log_regex) && matches.size() == 5) {
        entry.timestamp = matches[1].str();
        entry.level = matches[2].str();
        entry.component = matches[3].str();
        entry.message = matches[4].str();
    } else {
        // Try simpler format: LEVEL COMPONENT: MESSAGE
        std::regex simple_regex(R"((\w+)\s+([^:]+):\s*(.*))", std::regex_constants::icase);
        if (std::regex_match(line, matches, simple_regex) && matches.size() == 4) {
            entry.level = matches[1].str();
            entry.component = matches[2].str();
            entry.message = matches[3].str();
            entry.timestamp = ""; // No timestamp in this format
        } else {
            // Fallback: treat as generic message
            entry.level = "INFO";
            entry.component = "System";
        }
    }

    return entry;
}

std::vector<IncrementalLogEntry> IncrementalLogReader::readLinesFromFile(size_t start_line, size_t max_lines) const {
    std::vector<IncrementalLogEntry> entries;

    std::ifstream file(log_file_path_);
    if (!file.is_open()) {
        return entries;
    }

    std::string line;
    size_t current_line = 0;
    size_t lines_read = 0;

    // Skip to start line
    while (current_line < start_line && std::getline(file, line)) {
        current_line++;
    }

    // Read requested lines
    while (lines_read < max_lines && std::getline(file, line)) {
        IncrementalLogEntry entry = parseLogLine(line, current_line);
        entries.push_back(entry);

        current_line++;
        lines_read++;
    }

    file.close();
    return entries;
}

size_t IncrementalLogReader::countLinesInFile() const {
    std::ifstream file(log_file_path_);
    if (!file.is_open()) {
        return 0;
    }

    size_t line_count = 0;
    std::string line;
    while (std::getline(file, line)) {
        line_count++;
    }

    file.close();
    return line_count;
}

void IncrementalLogReader::cleanupOldSessions() {
    time_t now = time(nullptr);

    auto it = sessions_.begin();
    while (it != sessions_.end()) {
        if ((now - it->second.last_access) > SESSION_TIMEOUT_SEC) {
            LOG_INFOF(TAG, "Cleaning up expired session: %s", it->first.c_str());
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string IncrementalLogReader::generateSessionId() const {
    // Simple session ID generation using timestamp and random component
    uint64_t timestamp = esp_timer_get_time();
    uint32_t random_part = esp_random();

    std::ostringstream oss;
    oss << "sess_" << std::hex << timestamp << "_" << random_part;
    return oss.str();
}