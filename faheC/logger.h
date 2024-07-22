// logger.h
#ifndef LOGGER_H
#define LOGGER_H

enum LogLevel {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL
};

void logMessage(enum LogLevel level, const char* message);

#endif