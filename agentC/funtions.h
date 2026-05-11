/**
 * @file funtions.h
 * @brief Filesystem utilities: directory reading and string validation.
 *
 * @author Luis Fierro <luisfierroor@gmail.com>
 * @date 2026
 *
 * @note Development assisted by Claude (Anthropic) — claude.ai/code
 */

#ifndef FUNTIONS_H
#define FUNTIONS_H

#define _DEFAULT_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * @brief Information about a scanned directory.
 *
 * Holds separate lists of subdirectories and files found
 * when reading a path with readDirectory().
 */
struct directoryInformation {
    int directoryCount;    /**< Number of subdirectories found.  */
    char **directoryNames; /**< Array of subdirectory names.     */
    int fileCount;         /**< Number of files found.           */
    char **fileNames;      /**< Array of file names.             */
};

/**
 * @brief Reads a directory and classifies entries into subdirectories and files.
 *
 * @param path Absolute path of the directory to read.
 * @return Pointer to a directoryInformation struct, or NULL on error.
 *         The caller is responsible for freeing the memory.
 */
struct directoryInformation *readDirectory(const char *path);

/**
 * @brief Allocates a directoryInformation struct with capacity for @p size entries
 *        in each list.
 *
 * @param size Maximum number of entries to reserve for each list.
 * @return Pointer to the initialised struct, or NULL if allocation fails.
 */
struct directoryInformation *reserveMemory(int size);

/**
 * @brief Returns 1 if every character in str is a decimal digit, 0 otherwise.
 *
 * Used to identify PID entries in /proc (numeric directory names only).
 *
 * @param str Null-terminated string to evaluate.
 * @return 1 if all characters are digits, 0 otherwise.
 */
int isDigitString(const char *str);

#endif
