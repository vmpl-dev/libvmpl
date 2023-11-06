
#include <string.h>
#include <stdlib.h>

#include "env.h"

const char* get_env_or_default(const char* name, const char *default_value)
{
    const char* env = getenv(name);
    if (NULL == getenv(name)) {
        return default_value;
    }

    return env;
}