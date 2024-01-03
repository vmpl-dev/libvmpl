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
void log_init();
void log_message(int level, const char *format, ...);

#ifndef pr_fmt(fmt)
#define pr_fmt(fmt) "%s: " fmt, __func__
#endif

#if defined(__clang__)
// Clang-specific code
#define log_trace(fmt, ...) log_message(LOG_LEVEL_TRACE, pr_fmt(fmt), ##__VA_ARGS__)
#define log_debug(fmt, ...) log_message(LOG_LEVEL_DEBUG, pr_fmt(fmt), ##__VA_ARGS__)
#define log_info(fmt, ...) log_message(LOG_LEVEL_INFO, pr_fmt(fmt), ##__VA_ARGS__)
#define log_success(fmt, ...) log_message(LOG_LEVEL_SUCCESS, pr_fmt(fmt), ##__VA_ARGS__)
#define log_warn(fmt, ...) log_message(LOG_LEVEL_WARN, pr_fmt(fmt), ##__VA_ARGS__)
#define log_err(fmt, ...) log_message(LOG_LEVEL_ERROR, pr_fmt(fmt), ##__VA_ARGS__)
#define log_fatal(fmt, ...) log_message(LOG_LEVEL_FATAL, pr_fmt(fmt), ##__VA_ARGS__)
#elif defined(__GNUC__) || defined(__GNUG__)
// GCC-specific code
#define log_trace(fmt, args...) log_message(LOG_LEVEL_TRACE, pr_fmt(fmt), ##args)
#define log_debug(fmt, args...) log_message(LOG_LEVEL_DEBUG, pr_fmt(fmt), ##args)
#define log_info(fmt, args...) log_message(LOG_LEVEL_INFO, pr_fmt(fmt), ##args)
#define log_success(fmt, args...) log_message(LOG_LEVEL_SUCCESS, pr_fmt(fmt), ##args)
#define log_warn(fmt, args...) log_message(LOG_LEVEL_WARN, pr_fmt(fmt), ##args)
#define log_err(fmt, args...) log_message(LOG_LEVEL_ERROR, pr_fmt(fmt), ##args)
#define log_fatal(fmt, args...) log_message(LOG_LEVEL_FATAL, pr_fmt(fmt), ##args)
#endif

#endif /* LOG_H */