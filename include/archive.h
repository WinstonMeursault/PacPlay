#ifndef ARCHIVE_H
#define ARCHIVE_H

#define ARCHIVE_SUCC (0)
#define ARCHIVE_FAIL (-1)

/**
 * @brief Extract a .tar.gz archive to a destination directory.
 *
 * Decompresses the gzip layer via zlib-ng, then extracts tar entries
 * (directories and regular files) into @p destDir.  Intermediate
 * directories are created as needed via platformMkdirp().
 *
 * @param tarGzPath  Path to the .tar.gz file.
 * @param destDir    Destination directory (must exist).
 * @return @c ARCHIVE_SUCC on success, @c ARCHIVE_FAIL on failure.
 */
int extractTarGz(const char *tarGzPath, const char *destDir);

/**
 * @brief Create a .tar.gz archive from a source directory.
 *
 * Recursively walks @p sourceDir and packs all files and subdirectories
 * into a gzip-compressed tar archive at @p destPath.
 *
 * @param sourceDir  Source directory to pack.
 * @param destPath   Destination .tar.gz file path.
 * @return @c ARCHIVE_SUCC on success, @c ARCHIVE_FAIL on failure.
 */
int createTarGz(const char *sourceDir, const char *destPath);

#endif /* ARCHIVE_H */
