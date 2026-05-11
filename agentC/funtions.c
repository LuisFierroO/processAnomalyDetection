/**
 * @file funtions.c
 * @brief Filesystem utility implementations.
 *
 * @author Luis Fierro <luisfierroor@gmail.com>
 * @date 2026
 *
 * @note Development assisted by Claude (Anthropic) — claude.ai/code
 */

#include "funtions.h"

/**
 * @brief Reads a directory and classifies entries into subdirectories and files.
 *
 * Uses two passes over the directory: the first counts entries to allocate
 * exactly the right capacity, the second fills the arrays. This avoids the
 * fixed-size overflow that occurs in /proc when the process count exceeds
 * the preallocated capacity.
 *
 * Skips the "." and ".." entries.
 *
 * @param path Absolute path of the directory to read.
 * @return Pointer to a directoryInformation struct, or NULL on error.
 *         The caller is responsible for freeing the memory.
 */
struct directoryInformation *readDirectory(const char *path) {

    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return NULL;
    }

    /* First pass: count entries to determine required capacity */
    int dir_count = 0, file_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' ||
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
            continue;
        if (entry->d_type == DT_DIR) dir_count++;
        else                         file_count++;
    }
    rewinddir(dir);

    int capacity = (dir_count > file_count ? dir_count : file_count) + 1;
    struct directoryInformation *dirInfo = reserveMemory(capacity);
    if (!dirInfo) {
        closedir(dir);
        return NULL;
    }

    /* Second pass: fill arrays */
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' ||
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
            continue;
        if (entry->d_type == DT_DIR) {
            strncpy(dirInfo->directoryNames[dirInfo->directoryCount],
                    entry->d_name, 255);
            dirInfo->directoryNames[dirInfo->directoryCount++][255] = '\0';
        } else {
            strncpy(dirInfo->fileNames[dirInfo->fileCount],
                    entry->d_name, 255);
            dirInfo->fileNames[dirInfo->fileCount++][255] = '\0';
        }
    }

    closedir(dir);
    return dirInfo;
}

/**
 * @brief Allocates a directoryInformation struct with capacity for @p size entries
 *        in each list.
 *
 * @param size Maximum number of entries per list (directories and files).
 * @return Pointer to the initialized struct, or NULL if any allocation fails.
 */
struct directoryInformation *reserveMemory(int size) {

    struct directoryInformation *dirInfo = malloc(sizeof(struct directoryInformation));
    if (!dirInfo) {
        perror("malloc reserveMemory");
        return NULL;
    }

    dirInfo->directoryNames = malloc(sizeof(char *) * size);
    dirInfo->fileNames      = malloc(sizeof(char *) * size);

    if (!dirInfo->directoryNames || !dirInfo->fileNames) {
        perror("malloc reserveMemory");
        free(dirInfo->directoryNames);
        free(dirInfo->fileNames);
        free(dirInfo);
        return NULL;
    }

    for (int i = 0; i < size; i++) {
        dirInfo->directoryNames[i] = malloc(256);
        dirInfo->fileNames[i]      = malloc(256);
        if (!dirInfo->directoryNames[i] || !dirInfo->fileNames[i]) {
            for (int j = 0; j < i; j++) {
                free(dirInfo->directoryNames[j]);
                free(dirInfo->fileNames[j]);
            }
            free(dirInfo->directoryNames[i]);
            free(dirInfo->fileNames[i]);
            free(dirInfo->directoryNames);
            free(dirInfo->fileNames);
            free(dirInfo);
            return NULL;
        }
    }

    dirInfo->directoryCount = 0;
    dirInfo->fileCount      = 0;

    return dirInfo;
}

/**
 * @brief Returns 1 if every character in str is a decimal digit, 0 otherwise.
 *
 * Used to identify PID entries in /proc (numeric directory names only).
 *
 * @param str Null-terminated string to evaluate.
 */
int isDigitString(const char *str) {
    if (!str || str[0] == '\0') return 0;
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}
