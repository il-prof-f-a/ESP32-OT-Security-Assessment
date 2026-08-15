#pragma once
#include <string>
#include <map>
#include <vector>

// No StorageManager dependency needed

/**
 * Simple template engine for ESP32 web server
 * Supports placeholder replacement in HTML templates
 */
class TemplateEngine {
public:
    /**
     * Load template from embedded resource or filesystem
     * @param template_name Template identifier (e.g., "dashboard", "login")
     * @param template_data Raw template data
     * @return true if loaded successfully
     */
    bool loadTemplate(const std::string& template_name, const std::string& template_data);

    /**
     * Load template from file
     * @param template_name Template identifier
     * @param file_path Path to template file
     * @param storage Storage manager for file access
     * @return true if loaded successfully
     */
    bool loadTemplateFromFile(const std::string& template_name, const std::string& file_path);

    /**
     * Render template with placeholder replacement
     * @param template_name Template to render
     * @param variables Map of placeholder->value pairs
     * @return Rendered HTML string
     */
    std::string render(const std::string& template_name, const std::map<std::string, std::string>& variables = {});

    /**
     * Quick render with common system variables
     * @param template_name Template to render
     * @param custom_vars Additional variables to add
     * @return Rendered HTML with system variables
     */
    std::string renderWithSystemVars(const std::string& template_name, const std::map<std::string, std::string>& custom_vars = {});

    /**
     * Set global system variables (device info, version, etc.)
     */
    void setSystemVariables(const std::map<std::string, std::string>& sys_vars);

    /**
     * Direct placeholder replacement without loading template
     * @param template_str Template string with {{placeholder}} syntax
     * @param variables Map of placeholder->value pairs
     * @return Processed string with placeholders replaced
     */
    static std::string renderDirect(const std::string& template_str, const std::map<std::string, std::string>& variables = {});

private:
    std::map<std::string, std::string> templates_;
    std::map<std::string, std::string> system_vars_;

    /**
     * Replace all {{placeholder}} with corresponding values
     */
    std::string replacePlaceholders(const std::string& template_str, const std::map<std::string, std::string>& vars);
};