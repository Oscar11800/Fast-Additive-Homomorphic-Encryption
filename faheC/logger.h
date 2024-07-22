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

void log_message(LogLevel level, const char* format,...);

#endif