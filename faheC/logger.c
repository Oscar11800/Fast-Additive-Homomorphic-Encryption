#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

// Default log level (can be changed externally)
LogLevel current_log_level = LOG_FATAL;

#define RESET_COLOR "\033[0m"
#define RED_COLOR "\033[31m"
#define YELLOW_COLOR "\033[33m"
#define GREEN_COLOR "\033[32m"
#define BLUE_COLOR "\033[34m"

void log_message(LogLevel level, const char* format, ...) {
  if (level >= current_log_level) {
    va_list args;
    va_start(args, format);
    switch (level) {
      case LOG_DEBUG:
        printf("[DEBUG] ");
        printf(GREEN_COLOR);
        break;
      case LOG_INFO:
        printf("[INFO] ");
        printf(BLUE_COLOR);
        break;
      case LOG_WARNING:
        printf("[WARNING] ");
        printf(YELLOW_COLOR);
        break;
      case LOG_ERROR:
        printf("[ERROR] ");
        printf(RED_COLOR);
        break;
      case LOG_FATAL:
        printf(RED_COLOR "[FATAL] ");
        break;
      default:
        break;
    }
    vprintf(format, args);
    printf(RESET_COLOR
           "\n");  // Add a newline for better readability and reset color
    va_end(args);
  }
}