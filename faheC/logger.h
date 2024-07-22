// logger.h
#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL
}LogLevel;

#ifdef ENABLE_LOGGING
void log_message(LogLevel level, const char* format,...);
#else
#define log_message(level, format, ...) ((void)0) // Do nothing
#endif

#endif // LOGGER_H