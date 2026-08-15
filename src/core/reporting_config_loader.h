#pragma once

#include "configuration_manager.h"
#include "reporting_engine.h"
#include "log_file_manager.h"

namespace ReportingConfig {
    void loadFromConfig(ConfigurationManager* cfg, ReportingEngine* rep);
    void registerNetworkEndpoints(ConfigurationManager* cfg, ReportingEngine* rep);
    bool registerEmailFromConfig(ConfigurationManager* cfg, ReportingEngine* rep);
    bool isEmailRegistered();
    LogFileManager* getLogFileManager();
}
