/* Ordered key/value parsing of one systemd unit-file section. */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssc.h"

void kv_list_init(kv_list_t *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void kv_list_free(kv_list_t *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].key);
        free(list->items[i].value);
    }
    free(list->items);
    kv_list_init(list);
}

void kv_list_append(kv_list_t *list, const char *key, const char *value) {
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 16;
        kv_pair_t *grown = realloc(list->items, new_cap * sizeof(kv_pair_t));
        if (!grown) {
            perror("realloc");
            exit(1);
        }
        list->items = grown;
        list->capacity = new_cap;
    }
    list->items[list->count].key = strdup(key);
    list->items[list->count].value = strdup(value);
    list->count++;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int strcasecmp_(const char *a, const char *b) {
    for (;; a++, b++) {
        int ca = tolower((unsigned char)*a), cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        if (ca == '\0') return 0;
    }
}

int parse_unit_section(const char *path, const char *section, kv_list_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    kv_list_init(out);

    int in_section = 0;
    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        /* strip newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        char *trimmed = trim(line);
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') continue;

        size_t tlen = strlen(trimmed);
        if (trimmed[0] == '[' && trimmed[tlen - 1] == ']') {
            trimmed[tlen - 1] = '\0';
            char *name = trim(trimmed + 1);
            in_section = strcasecmp_(name, section) == 0;
            continue;
        }
        if (!in_section) continue;

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);
        kv_list_append(out, key, value);
    }
    fclose(f);
    return 0;
}

char *kv_merge(const kv_list_t *list, const char *key) {
    char *result = NULL;
    size_t result_len = 0;
    int found = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].key, key) != 0) continue;
        found = 1;
        const char *value = list->items[i].value;
        if (*value == '\0') continue; /* empty assignment resets, nothing to append */
        size_t vlen = strlen(value);
        size_t add = vlen + (result_len ? 1 : 0);
        char *grown = realloc(result, result_len + add + 1);
        if (!grown) {
            perror("realloc");
            exit(1);
        }
        result = grown;
        if (result_len) {
            result[result_len] = ' ';
            memcpy(result + result_len + 1, value, vlen + 1);
        } else {
            memcpy(result, value, vlen + 1);
        }
        result_len += add;
    }
    if (!found) return NULL;
    if (!result) {
        result = strdup(""); /* found but only ever assigned empty */
    }
    return result;
}

int kv_has(const kv_list_t *list, const char *key) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].key, key) == 0) return 1;
    }
    return 0;
}
