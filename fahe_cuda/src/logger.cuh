
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL,
    NONE
}LogLevel;


void log_message(LogLevel level, const char* format,...);

