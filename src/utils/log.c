#include "env.h"
#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define TIME_FORMAT "%d %b %Y %H:%M:%S"

static int log_level = LOG_LEVEL_INFO;
static bool show_time = false;

static const char *level_str[] = {
    "TRACE",
    "DEBUG",
    "INFO",
    "SUCCESS",
    "WARN",
    "ERROR",
    "FATAL",
    "UNKNOWN"
};

static const char *level_color[] = {
    COLOR_MAGENTA,
    COLOR_BLUE,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_RED,
    COLOR_PURPLE,
    COLOR_RESET
};

void set_log_level(int level) {
    if (level >= LOG_LEVEL_TRACE && level <= LOG_LEVEL_FATAL)
        log_level = level;
    else
        log_level = LOG_LEVEL_INFO;
}

void set_log_level_str(const char *level_str) {
	if (strcmp(level_str, "trace") == 0) {
		log_level = LOG_LEVEL_TRACE;
	} else if (strcmp(level_str, "debug") == 0) {
		log_level = LOG_LEVEL_DEBUG;
	} else if (strcmp(level_str, "info") == 0) {
		log_level = LOG_LEVEL_INFO;
	} else if (strcmp(level_str, "success") == 0) {
		log_level = LOG_LEVEL_SUCCESS;
	} else if (strcmp(level_str, "warn") == 0) {
		log_level = LOG_LEVEL_WARN;
	} else if (strcmp(level_str, "error") == 0) {
		log_level = LOG_LEVEL_ERROR;
	} else if (strcmp(level_str, "fatal") == 0) {
		log_level = LOG_LEVEL_FATAL;
	} else {
		log_level = LOG_LEVEL_INFO;
	}
}

void set_show_time(bool show) {
    show_time = show;
}

void log_init() {
	const char *log_level_str;
	const char *show_time_str;

    log_level_str = get_env_or_default("VMPL_LOG_LEVEL", "info");
    set_log_level_str(log_level_str);

    show_time_str = get_env_or_default("VMPL_LOG_SHOW_TIME", "false");
    set_show_time(strcmp(show_time_str, "true") == 0);
}

int padding_str(char text[10]) {
    int padding = (10 - strlen(text)) / 2;
    
    printf("%*s%s%*s\n", padding, "", text, padding, "");
    
    return 0;
}

void log_message(int level, const char *format, ...) {
    if (level < log_level) {
        return;
    }

    const char *level_str_ptr = level_str[level];
    const char *level_color_ptr = level_color[level];

    va_list args;
    va_start(args, format);
    char message[1024];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    if (show_time) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), TIME_FORMAT, tm);
        printf("%s[%s] [%s] %s%s\n", level_color_ptr, time_str, level_str_ptr, message, COLOR_RESET);
    } else {
        printf("%s[%s] %s%s\n", level_color_ptr, level_str_ptr, message, COLOR_RESET);
    }
}