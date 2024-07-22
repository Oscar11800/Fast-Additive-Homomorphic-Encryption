#include <stdio.h>
#include "logger.h"

// Function to log a message
// logger.c

#include <stdio.h>
#include "logger.h"

// Default log level (can be changed externally)
static LogLevel current_log_level = LEVEL_INFO;

void log_message(LogLevel level, const char* format, ...) {
    if (level >= current_log_level) {
        va_list args;
        va_start(args, format);
        switch (level) {
            case LEVEL_DEBUG:
                printf("[DEBUG] ");
                break;
            case LEVEL_INFO:
                printf("[INFO] ");
                break;
            case LEVEL_WARNING:
                printf("[WARNING] ");
                break;
            case LEVEL_ERROR:
                printf("[ERROR] ");
                break;
            case LEVEL_FATAL:
                printf("[FATAL] ");
                break;
            default:
                break;
        }
        vprintf(format, args);
        va_end(args);
    }
}