#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_INFO
#endif

static inline const char* log_level_str(int level) {
    switch (level) {
        case LOG_DEBUG: return "DBG";
        case LOG_INFO: return "INF";
        case LOG_WARN: return "WRN";
        case LOG_ERROR: return "ERR";
        default: return "???";
    }
}

static inline void log_printf(int level, const char* func, int line, const char* fmt, ...) {
    if (level < LOG_LEVEL) {
        return;
    }

    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    struct tm tm;
    localtime_r(&spec.tv_sec, &tm);

    fprintf(stderr, "%02d:%02d:%02d.%03ld [%s] %s:%d: ", 
        tm.tm_hour, tm.tm_min, tm.tm_sec, spec.tv_nsec / 1000000, 
        log_level_str(level), func, line
    );

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#define log_debug(...) log_printf(LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_printf(LOG_INFO,  __func__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_printf(LOG_WARN,  __func__, __LINE__, __VA_ARGS__)
#define log_error(...) log_printf(LOG_ERROR, __func__, __LINE__, __VA_ARGS__)

#endif