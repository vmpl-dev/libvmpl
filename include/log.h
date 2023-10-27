#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

#define LOG_LEVEL_TRACE 0
#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_SUCCESS 3
#define LOG_LEVEL_WARN 4
#define LOG_LEVEL_ERROR 5
#define LOG_LEVEL_FATAL 6

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_GREEN "\033[32m"
#define COLOR_PURPLE "\033[35m"

void set_log_level(int level);
void set_log_level_str(const char *level_str);
void set_show_time(bool show);
void log_message(int level, const char *format, ...);

#define log_trace(fmt, ...) log_message(LOG_LEVEL_TRACE, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) log_message(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log_message(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define log_success(fmt, ...) log_message(LOG_LEVEL_SUCCESS, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_message(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define log_err(fmt, ...) log_message(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define log_fatal(fmt, ...) log_message(LOG_LEVEL_FATAL, fmt, ##__VA_ARGS__)

#endif /* LOG_H */