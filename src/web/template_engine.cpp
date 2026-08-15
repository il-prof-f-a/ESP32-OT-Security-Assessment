#include "template_engine.h"
#include "../core/logging_system.h"
#include "../core/async_storage_engine.h"
#include <regex>

bool TemplateEngine::loadTemplate(const std::string& template_name, const std::string& template_data) {
    if (template_data.empty()) {
        LOG_ERRORF("TemplateEngine", "Empty template data for '%s'", template_name.c_str());
        return false;
    }

    templates_[template_name] = template_data;
    LOG_INFOF("TemplateEngine", "Loaded template '%s' (%d bytes)", template_name.c_str(), (int)template_data.size());
    return true;
}

bool TemplateEngine::loadTemplateFromFile(const std::string& template_name, const std::string& file_path) {
    std::string template_data;
    if (AsyncStorage::Global::readFile(file_path, template_data) != ESP_OK) {
        LOG_ERRORF("TemplateEngine", "Failed to read template file '%s' for template '%s'", file_path.c_str(), template_name.c_str());
        return false;
    }

    if (template_data.empty()) {
        LOG_ERRORF("TemplateEngine", "Empty template file '%s' for template '%s'", file_path.c_str(), template_name.c_str());
        return false;
    }

    templates_[template_name] = template_data;
    LOG_INFOF("TemplateEngine", "Loaded template '%s' from file '%s' (%d bytes)",
              template_name.c_str(), file_path.c_str(), (int)template_data.size());
    return true;
}

std::string TemplateEngine::render(const std::string& template_name, const std::map<std::string, std::string>& variables) {
    auto it = templates_.find(template_name);
    if (it == templates_.end()) {
        LOG_ERRORF("TemplateEngine", "Template '%s' not found", template_name.c_str());
        return "<html><body><h1>Template Error</h1><p>Template '" + template_name + "' not found</p></body></html>";
    }

    return replacePlaceholders(it->second, variables);
}

std::string TemplateEngine::renderWithSystemVars(const std::string& template_name, const std::map<std::string, std::string>& custom_vars) {
    // Merge system variables with custom variables (custom vars override system vars)
    std::map<std::string, std::string> all_vars = system_vars_;
    for (const auto& pair : custom_vars) {
        all_vars[pair.first] = pair.second;
    }

    return render(template_name, all_vars);
}

void TemplateEngine::setSystemVariables(const std::map<std::string, std::string>& sys_vars) {
    system_vars_ = sys_vars;
    LOG_INFOF("TemplateEngine", "Set %d system variables", (int)sys_vars.size());
}

std::string TemplateEngine::replacePlaceholders(const std::string& template_str, const std::map<std::string, std::string>& vars) {
    std::string result = template_str;

    // Simple string replacement approach (more efficient than regex for ESP32)
    for (const auto& pair : vars) {
        std::string placeholder = "{{" + pair.first + "}}";
        size_t pos = 0;

        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), pair.second);
            pos += pair.second.length();
        }
    }

    // Log any remaining unreplaced placeholders for debugging
    size_t pos = 0;
    while ((pos = result.find("{{", pos)) != std::string::npos) {
        size_t end_pos = result.find("}}", pos + 2);
        if (end_pos != std::string::npos) {
            std::string unreplaced = result.substr(pos + 2, end_pos - pos - 2);
            LOG_WARNINGF("TemplateEngine", "Unreplaced placeholder: {{%s}}", unreplaced.c_str());
            pos = end_pos + 2;
        } else {
            break;
        }
    }

    return result;
}

std::string TemplateEngine::renderDirect(const std::string& template_str, const std::map<std::string, std::string>& variables) {
    std::string result = template_str;

    // Simple string replacement approach (more efficient than regex for ESP32)
    for (const auto& pair : variables) {
        std::string placeholder = "{{" + pair.first + "}}";
        size_t pos = 0;

        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), pair.second);
            pos += pair.second.length();
        }
    }

    return result;
}