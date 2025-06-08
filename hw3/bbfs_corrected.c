/*
  Big Brother File System
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  This code is derived from function prototypes found /usr/include/fuse/fuse.h
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  His code is licensed under the LGPLv2.
  A copy of that code is included in the file fuse.h
  
  The point of this FUSE filesystem is to provide an introduction to
  FUSE.  It was my first FUSE filesystem as I got to know the
  software; hopefully, the comments in this code will help people who
  follow later to get a gentler introduction.

  This might be called a no-op filesystem:  it doesn't impose
  filesystem semantics on top of any other existing structure.  It
  simply reports the requests that come in, and passes them to an
  underlying filesystem.  The information is saved in a logfile named
  bbfs.log, in the directory from which you run bbfs.
*/
#include <jansson.h>
#include "config.h"
#include "params.h"
#include <openssl/sha.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif
#define BLOCK_SIZE 4096
#include "log.h"
static void sha1_to_hex(const unsigned char *sha1_hash, char *hex_out) {
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(hex_out + (i * 2), "%02x", sha1_hash[i]);
    }
    hex_out[SHA_DIGEST_LENGTH * 2] = 0; // Null terminate the string
}
//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, BB_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
				    // break here

    log_msg("    bb_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
	    BB_DATA->rootdir, path, fpath);
}
//
/**
 * Loads a JSON object from a metadata file.
 * Returns a new json_t object that must be decref'd, or NULL on error.
 */
static json_t *load_metadata_json(const char *fpath) {
    json_error_t error;
    json_t *root = json_load_file(fpath, 0, &error);
    if (!root) {
        log_msg("    JSON ERROR: on line %d: %s\n", error.line, error.text);
        return NULL;
    }
    return root;
}

/**
 * Saves a JSON object to a metadata file.
 * Returns 0 on success, -1 on failure.
 */
static int save_metadata_json(const char *fpath, json_t *root) {
    if (json_dump_file(root, fpath, JSON_INDENT(2)) < 0) {
        log_msg("    JSON ERROR: failed to write to file %s\n", fpath);
        return -1;
    }
    return 0;
}

/**
 * Increments the reference count for a given block hash.
 * If the block is new, creates the refcount file and the block data file.
 */
static int increment_block_refcount(const char *hex_hash, const char *block_data) {
    char fpath[PATH_MAX];
    bb_fullpath(fpath, "/hashes/");
    strcat(fpath, hex_hash);

    int ref_count = 1;
    int is_new = 1;

    int fd = open(fpath, O_RDWR);
    if (fd >= 0) {
        char buffer[32];
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            ref_count = atoi(buffer) + 1;
            is_new = 0;
        }
        lseek(fd, 0, SEEK_SET);
    } else {
        fd = open(fpath, O_CREAT | O_WRONLY, 0644);
    }

    if (fd < 0) return -errno;

    char count_str[32];
    int len = snprintf(count_str, sizeof(count_str), "%d", ref_count);
    write(fd, count_str, len);
    close(fd);

    if (is_new && block_data) {
        bb_fullpath(fpath, "/blocks/");
        strcat(fpath, hex_hash);
        int block_fd = open(fpath, O_CREAT | O_WRONLY, 0644);
        if (block_fd < 0) return -errno;
        write(block_fd, block_data, BLOCK_SIZE);
        close(block_fd);
    }
    
    return 0;
}

/**
 * Decrements the reference count for a given block hash.
 * If the count reaches zero, deletes the refcount and data files.
 */
static int decrement_block_refcount(const char *hex_hash) {
    char hash_fpath[PATH_MAX];
    bb_fullpath(hash_fpath, "/hashes/");
    strcat(hash_fpath, hex_hash);

    int fd = open(hash_fpath, O_RDWR);
    if (fd < 0) return -errno;

    char buffer[32];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        int ref_count = atoi(buffer) - 1;

        if (ref_count <= 0) {
            close(fd);
            unlink(hash_fpath); // Delete refcount file

            char block_fpath[PATH_MAX];
            bb_fullpath(block_fpath, "/blocks/");
            strcat(block_fpath, hex_hash);
            unlink(block_fpath); // Delete data block file
        } else {
            char count_str[32];
            int len = snprintf(count_str, sizeof(count_str), "%d", ref_count);
            lseek(fd, 0, SEEK_SET);
            ftruncate(fd, 0);
            write(fd, count_str, len);
            close(fd);
        }
    } else {
        close(fd);
    }

    return 0;
}
//



////////////////////////
/*
metadata file
1st path
2nd ubuf
3... hashes
*/
////////////////////////


/**
 * Calculates the SHA1 hash of a virtual path string.
 * This is used to create a unique filename for the corresponding metadata file.
 * The resulting filename is a 40-character hexadecimal string.
 */
static void get_metadata_filename(const char *path, char *metadata_filename_hex) {
    unsigned char hash[SHA_DIGEST_LENGTH]; // Buffer for the 20-byte binary hash

    // Calculate the SHA1 hash of the path using the OpenSSL library.
    SHA1((const unsigned char *)path, strlen(path), hash);

    // Convert the binary hash into a printable hexadecimal string.
    sha1_to_hex(hash, metadata_filename_hex);
}


///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int bb_getattr(const char *path, struct stat *statbuf) {
    char fpath[PATH_MAX];
    char metadata_fname[41];

    log_msg("\nbb_getattr(path=\"%s\", ...)\n", path);
    memset(statbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        bb_fullpath(fpath, "/");
        if (lstat(fpath, statbuf) < 0) return -errno;
        return 0;
    }

    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    json_t *root = load_metadata_json(fpath);
    if (!root) return -ENOENT;

    statbuf->st_mode = json_integer_value(json_object_get(root, "mode"));
    statbuf->st_uid = json_integer_value(json_object_get(root, "uid"));
    statbuf->st_gid = json_integer_value(json_object_get(root, "gid"));
    statbuf->st_atime = json_integer_value(json_object_get(root, "atime"));
    statbuf->st_mtime = json_integer_value(json_object_get(root, "mtime"));
    
    json_t *hashes = json_object_get(root, "hashes");
    statbuf->st_size = json_array_size(hashes) * BLOCK_SIZE;
    statbuf->st_nlink = 1;
    statbuf->st_blocks = json_array_size(hashes);
    statbuf->st_blksize = BLOCK_SIZE;

    json_decref(root);
    return 0;
}
// int bb_getattr(const char *path, struct stat *statbuf)
// {
//     int retstat;
//     char fpath[PATH_MAX];
    
//     log_msg("\nbb_getattr(path=\"%s\", statbuf=0x%08x)\n",
// 	  path, statbuf);
//     bb_fullpath(fpath, path);
        
//     retstat = log_syscall("lstat", lstat(fpath, statbuf), 0);
    
//     log_stat(statbuf);
    
//     return retstat;
// }

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
// Note the system readlink() will truncate and lose the terminating
// null.  So, the size passed to to the system readlink() must be one
// less than the size passed to bb_readlink()
// bb_readlink() code by Bernardo F Costa (thanks!)
int bb_readlink(const char *path, char *link, size_t size)
{
    int retstat;
    char fpath[PATH_MAX];
    
    log_msg("\nbb_readlink(path=\"%s\", link=\"%s\", size=%d)\n",
	  path, link, size);
    bb_fullpath(fpath, path);

    retstat = log_syscall("readlink", readlink(fpath, link, size - 1), 0);
    if (retstat >= 0) {
	link[retstat] = '\0';
	retstat = 0;
	log_msg("    link=\"%s\"\n", link);
    }
    
    return retstat;
}

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?
// int bb_mknod(const char *path, mode_t mode, dev_t dev)
// {
//     int retstat = 0;
//     char fpath[PATH_MAX];

//     log_msg("\nbb_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n",
//           path, mode, dev);


//     // 1. Declare variables for the hashing process.
//     unsigned char sha1_binary_hash[SHA_DIGEST_LENGTH]; // 20 bytes for raw SHA1
//     char metadata_filename_hex[41]; // 40 hex characters + 1 for null terminator

//     // 2. Calculate the raw SHA1 hash of the virtual path.
//     //    This is the logic from the get_metadata_filename() helper.
//     SHA1((const unsigned char *)path, strlen(path), sha1_binary_hash);

//     // 3. Convert the 20-byte binary hash into a 40-character hex string.
//     //    This is the logic from the sha1_to_hex() helper.
//     for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
//         sprintf(metadata_filename_hex + (i * 2), "%02x", sha1_binary_hash[i]);
//     }
//     metadata_filename_hex[SHA_DIGEST_LENGTH * 2] = 0; // Null terminate the string



//     log_msg("    bb_mknod: Inlined logic produced metadata filename: '%s'\n", metadata_filename_hex);

//     // 4. Construct the full real path to the new metadata file.
//     char metadata_rel_path[PATH_MAX];
//     snprintf(metadata_rel_path, PATH_MAX, "/metadata/%s", metadata_filename_hex);
//     bb_fullpath(fpath, metadata_rel_path);

//     log_msg("    bb_mknod: Creating metadata file at '%s'\n", fpath);

//     // 5. Create the empty metadata file.
//     if (S_ISREG(mode)) {
//         int fd = log_syscall("open", open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode), 0);
//         if (fd >= 0) {
//             log_msg("    bb_mknod: Init file structure\n", path);
//             // Write the original path as the first line of the metadata file.           
//             log_syscall("close", close(fd), 0);
//             retstat = 0;
//         } else {
//             retstat = fd;
//         }
//     } else {
//         retstat = -EPERM; // Operation not permitted for non-regular files
//     }
    
//     return retstat;
// }
int bb_mknod(const char *path, mode_t mode, dev_t dev) {
    char fpath[PATH_MAX];
    char metadata_fname[41];
    struct fuse_context *ctx = fuse_get_context();

    log_msg("\nbb_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n", path, mode, dev);

    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    // Create the JSON object for the new file
    json_t *root = json_object();
    json_object_set_new(root, "path", json_string(path));
    json_object_set_new(root, "mode", json_integer(mode));
    json_object_set_new(root, "uid", json_integer(ctx->uid));
    json_object_set_new(root, "gid", json_integer(ctx->gid));
    json_object_set_new(root, "atime", json_integer(time(NULL)));
    json_object_set_new(root, "mtime", json_integer(time(NULL)));
    json_object_set_new(root, "hashes", json_array()); // Empty array of block hashes

    // Save the JSON to the new metadata file
    if (save_metadata_json(fpath, root) != 0) {
        json_decref(root);
        return -EIO;
    }

    json_decref(root);
    return 0;
}
/** Create a directory */
int bb_mkdir(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];
    
    log_msg("\nbb_mkdir(path=\"%s\", mode=0%3o)\n",
	    path, mode);
    bb_fullpath(fpath, path);

    return log_syscall("mkdir", mkdir(fpath, mode), 0);
}

/** Remove a file */
int bb_unlink(const char *path) {
    char fpath[PATH_MAX];
    char metadata_fname[41];
    
    log_msg("bb_unlink(path=\"%s\")\n", path);

    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    json_t *root = load_metadata_json(fpath);
    if (!root) return -ENOENT;

    // Decrement refcount for all associated blocks
    json_t *hashes = json_object_get(root, "hashes");
    size_t i;
    json_t *value;
    json_array_foreach(hashes, i, value) {
        const char *hash_str = json_string_value(value);
        if (hash_str) {
            decrement_block_refcount(hash_str);
        }
    }
    
    json_decref(root);
    
    // Finally, delete the metadata file itself
    return unlink(fpath);
}

// int bb_unlink(const char *path)
// {
//     char fpath[PATH_MAX];
    
//     log_msg("bb_unlink(path=\"%s\")\n",
// 	    path);
//     bb_fullpath(fpath, path);

//     return log_syscall("unlink", unlink(fpath), 0);
// }

/** Remove a directory */
int bb_rmdir(const char *path)
{
    char fpath[PATH_MAX];
    
    log_msg("bb_rmdir(path=\"%s\")\n",
	    path);
    bb_fullpath(fpath, path);

    return log_syscall("rmdir", rmdir(fpath), 0);
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int bb_symlink(const char *path, const char *link)
{
    char flink[PATH_MAX];
    
    log_msg("\nbb_symlink(path=\"%s\", link=\"%s\")\n",
	    path, link);
    bb_fullpath(flink, link);

    return log_syscall("symlink", symlink(path, flink), 0);
}

/** Rename a file */
// both path and newpath are fs-relative
int bb_rename(const char *path, const char *newpath)
{
    char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];
    
    log_msg("\nbb_rename(fpath=\"%s\", newpath=\"%s\")\n",
	    path, newpath);
    bb_fullpath(fpath, path);
    bb_fullpath(fnewpath, newpath);

    return log_syscall("rename", rename(fpath, fnewpath), 0);
}

/** Create a hard link to a file */
int bb_link(const char *path, const char *newpath)
{
    char fpath[PATH_MAX], fnewpath[PATH_MAX];
    
    log_msg("\nbb_link(path=\"%s\", newpath=\"%s\")\n",
	    path, newpath);
    bb_fullpath(fpath, path);
    bb_fullpath(fnewpath, newpath);

    return log_syscall("link", link(fpath, fnewpath), 0);
}

/** Change the permission bits of a file */
int bb_chmod(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];
    
    log_msg("\nbb_chmod(fpath=\"%s\", mode=0%03o)\n",
	    path, mode);
    bb_fullpath(fpath, path);

    return log_syscall("chmod", chmod(fpath, mode), 0);
}

/** Change the owner and group of a file */
int bb_chown(const char *path, uid_t uid, gid_t gid)
  
{
    char fpath[PATH_MAX];
    
    log_msg("\nbb_chown(path=\"%s\", uid=%d, gid=%d)\n",
	    path, uid, gid);
    bb_fullpath(fpath, path);

    return log_syscall("chown", chown(fpath, uid, gid), 0);
}

/** Change the size of a file */
int bb_truncate(const char *path, off_t newsize)
{
    char fpath[PATH_MAX];
    
    log_msg("\nbb_truncate(path=\"%s\", newsize=%lld)\n",
	    path, newsize);
    bb_fullpath(fpath, path);

    return log_syscall("truncate", truncate(fpath, newsize), 0);
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
/** Change the access and/or modification times of a file */
int bb_utime(const char *path, struct utimbuf *ubuf) {
    char fpath[PATH_MAX];
    char metadata_fname[41];

    log_msg("\nbb_utime(path=\"%s\")\n", path);
    
    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    json_t *root = load_metadata_json(fpath);
    if (!root) return -ENOENT;

    json_object_set_new(root, "atime", json_integer(ubuf->actime));
    json_object_set_new(root, "mtime", json_integer(ubuf->modtime));

    save_metadata_json(fpath, root);
    json_decref(root);

    return 0;
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */
int bb_open(const char *path, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    char metadata_fname[41];
    log_msg("\nbb_open(path\"%s\", fi=0x%08x)\n", path, fi);

    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    // Open the metadata file itself to get a file handle.
    // This simplifies state management.
    int fd = open(fpath, fi->flags);
    if (fd < 0) return -errno;

    fi->fh = fd;
    
    // Update access time
    json_t *root = load_metadata_json(fpath);
    if (root) {
        json_object_set_new(root, "atime", json_integer(time(NULL)));
        save_metadata_json(fpath, root);
        json_decref(root);
    }
    
    return 0;
}
/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.
int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    char metadata_fname[41];
    size_t read_bytes = 0;

    log_msg("\nbb_read(path=\"%s\", size=%zu, offset=%lld)\n", path, size, offset);

    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    json_t *root = load_metadata_json(fpath);
    if (!root) return -EIO;

    json_t *hashes = json_object_get(root, "hashes");
    size_t max_size = json_array_size(hashes) * BLOCK_SIZE;

    // Read blocks one by one
    while (read_bytes < size) {
        off_t current_offset = offset + read_bytes;
        if (current_offset >= max_size) break; // End of file

        size_t block_idx = current_offset / BLOCK_SIZE;
        off_t offset_in_block = current_offset % BLOCK_SIZE;

        json_t *hash_json = json_array_get(hashes, block_idx);
        const char *hash_str = json_string_value(hash_json);
        if (!hash_str) break;

        char block_fpath[PATH_MAX];
        bb_fullpath(block_fpath, "/blocks/");
        strcat(block_fpath, hash_str);
        
        int block_fd = open(block_fpath, O_RDONLY);
        if (block_fd < 0) {
            // Handle "zero blocks" from truncate
            if (strlen(hash_str) == 0) {
                memset(buf + read_bytes, 0, BLOCK_SIZE);
                read_bytes += BLOCK_SIZE;
                continue;
            }
            break;
        }
        
        size_t bytes_to_read = (size - read_bytes > BLOCK_SIZE - offset_in_block) ? (BLOCK_SIZE - offset_in_block) : (size - read_bytes);

        ssize_t res = pread(block_fd, buf + read_bytes, bytes_to_read, offset_in_block);
        close(block_fd);

        if (res <= 0) break;
        read_bytes += res;
    }

    json_object_set_new(root, "atime", json_integer(time(NULL)));
    save_metadata_json(fpath, root);
    json_decref(root);

    return read_bytes;
}

// int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
// {
//     int retstat = 0;
    
//     log_msg("\nbb_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
// 	    path, buf, size, offset, fi);
//     // no need to get fpath on this one, since I work from fi->fh not the path
//     log_fi(fi);

//     return log_syscall("pread", pread(fi->fh, buf, size, offset), 0);
// }

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
// As  with read(), the documentation above is inconsistent with the
// documentation for the write() system call.
// int bb_write(const char *path, const char *buf, size_t size, off_t offset,
// 	     struct fuse_file_info *fi)
// {
//     int retstat = 0;
    
//     log_msg("\nbb_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
// 	    path, buf, size, offset, fi
// 	    );
//     // no need to get fpath on this one, since I work from fi->fh not the path
//     log_fi(fi);

//     return log_syscall("pwrite", pwrite(fi->fh, buf, size, offset), 0);
// }
// Update hash list to include new block hash at specific position
int bb_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    char metadata_fname[41];
    size_t written_bytes = 0;

    log_msg("\nbb_write(path=\"%s\", size=%zu, offset=%lld)\n", path, size, offset);

    get_metadata_filename(path, metadata_fname);
    bb_fullpath(fpath, "/metadata/");
    strcat(fpath, metadata_fname);

    json_t *root = load_metadata_json(fpath);
    if (!root) return -EIO;

    json_t *hashes = json_object_get(root, "hashes");
    if (!json_is_array(hashes)) {
        json_decref(root);
        return -EIO;
    }

    while (written_bytes < size) {
        off_t current_offset = offset + written_bytes;
        size_t block_idx = current_offset / BLOCK_SIZE;
        size_t bytes_to_write = BLOCK_SIZE;
        
        const char *block_data = buf + written_bytes;

        // Hash the new block
        unsigned char block_hash_bin[SHA_DIGEST_LENGTH];
        char block_hash_hex[41];
        SHA1((unsigned char*)block_data, BLOCK_SIZE, block_hash_bin);
        sha1_to_hex(block_hash_bin, block_hash_hex);

        // If we are overwriting an existing block, decrement its refcount
        if (block_idx < json_array_size(hashes)) {
            json_t *old_hash_json = json_array_get(hashes, block_idx);
            const char *old_hash_str = json_string_value(old_hash_json);
            if (old_hash_str && strlen(old_hash_str) > 0) {
                 decrement_block_refcount(old_hash_str);
            }
        }
        
        // Increment refcount for the new block (and write its data if new)
        increment_block_refcount(block_hash_hex, block_data);
        
        // Update the hashes array in our JSON object
        json_t *new_hash_json = json_string(block_hash_hex);
        if (block_idx < json_array_size(hashes)) {
            json_array_set_new(hashes, block_idx, new_hash_json);
        } else {
            // This handles appending to the file
            while (json_array_size(hashes) < block_idx) {
                json_array_append_new(hashes, json_string("")); // Pad with empty blocks if writing non-sequentially
            }
            json_array_append_new(hashes, new_hash_json);
        }
        
        written_bytes += bytes_to_write;
    }

    // Update metadata and save
    json_object_set_new(root, "mtime", json_integer(time(NULL)));
    save_metadata_json(fpath, root);
    json_decref(root);
    
    return size;
}
/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int bb_statfs(const char *path, struct statvfs *statv)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    log_msg("\nbb_statfs(path=\"%s\", statv=0x%08x)\n",
	    path, statv);
    bb_fullpath(fpath, path);
    
    // get stats for underlying filesystem
    retstat = log_syscall("statvfs", statvfs(fpath, statv), 0);
    
    log_statvfs(statv);
    
    return retstat;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
// this is a no-op in BBFS.  It just logs the call and returns success
int bb_flush(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nbb_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);
	
    return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int bb_release(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nbb_release(path=\"%s\", fi=0x%08x)\n",
	  path, fi);
    log_fi(fi);

    // We need to close the file.  Had we allocated any resources
    // (buffers etc) we'd need to free them here as well.
    return log_syscall("close", close(fi->fh), 0);
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int bb_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    log_msg("\nbb_fsync(path=\"%s\", datasync=%d, fi=0x%08x)\n",
	    path, datasync, fi);
    log_fi(fi);
    
    // some unix-like systems (notably freebsd) don't have a datasync call
#ifdef HAVE_FDATASYNC
    if (datasync)
	return log_syscall("fdatasync", fdatasync(fi->fh), 0);
    else
#endif	
	return log_syscall("fsync", fsync(fi->fh), 0);
}

#ifdef HAVE_SYS_XATTR_H
/** Note that my implementations of the various xattr functions use
    the 'l-' versions of the functions (eg bb_setxattr() calls
    lsetxattr() not setxattr(), etc).  This is because it appears any
    symbolic links are resolved before the actual call takes place, so
    I only need to use the system-provided calls that don't follow
    them */

/** Set extended attributes */
int bb_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    char fpath[PATH_MAX];
    
    log_msg("\nbb_setxattr(path=\"%s\", name=\"%s\", value=\"%s\", size=%d, flags=0x%08x)\n",
	    path, name, value, size, flags);
    bb_fullpath(fpath, path);

    return log_syscall("lsetxattr", lsetxattr(fpath, name, value, size, flags), 0);
}

/** Get extended attributes */
int bb_getxattr(const char *path, const char *name, char *value, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    log_msg("\nbb_getxattr(path = \"%s\", name = \"%s\", value = 0x%08x, size = %d)\n",
	    path, name, value, size);
    bb_fullpath(fpath, path);

    retstat = log_syscall("lgetxattr", lgetxattr(fpath, name, value, size), 0);
    if (retstat >= 0)
	log_msg("    value = \"%s\"\n", value);
    
    return retstat;
}

/** List extended attributes */
int bb_listxattr(const char *path, char *list, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char *ptr;
    
    log_msg("\nbb_listxattr(path=\"%s\", list=0x%08x, size=%d)\n",
	    path, list, size
	    );
    bb_fullpath(fpath, path);

    retstat = log_syscall("llistxattr", llistxattr(fpath, list, size), 0);
    if (retstat >= 0) {
	log_msg("    returned attributes (length %d):\n", retstat);
	if (list != NULL)
	    for (ptr = list; ptr < list + retstat; ptr += strlen(ptr)+1)
		log_msg("    \"%s\"\n", ptr);
	else
	    log_msg("    (null)\n");
    }
    
    return retstat;
}

/** Remove extended attributes */
int bb_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];
    
    log_msg("\nbb_removexattr(path=\"%s\", name=\"%s\")\n",
	    path, name);
    bb_fullpath(fpath, path);

    return log_syscall("lremovexattr", lremovexattr(fpath, name), 0);
}
#endif

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
/** Open directory */
int bb_opendir(const char *path, struct fuse_file_info *fi) {
    DIR *dp;
    char fpath[PATH_MAX];
    
    log_msg("\nbb_opendir(path=\"%s\", fi=0x%08x)\n", path, fi);
    
    // This filesystem is flat. We can only open the root directory.
    if (strcmp(path, "/") != 0) return -ENOENT;

    bb_fullpath(fpath, "/metadata");
    dp = opendir(fpath);
    if (dp == NULL) return -errno;
    
    fi->fh = (intptr_t) dp;
    return 0;
}

// int bb_opendir(const char *path, struct fuse_file_info *fi)
// {
//     DIR *dp;
//     int retstat = 0;
//     char fpath[PATH_MAX];
    
//     log_msg("\nbb_opendir(path=\"%s\", fi=0x%08x)\n",
// 	  path, fi);
//     bb_fullpath(fpath, path);

//     // since opendir returns a pointer, takes some custom handling of
//     // return status.
//     dp = opendir(fpath);
//     log_msg("    opendir returned 0x%p\n", dp);
//     if (dp == NULL)
// 	retstat = log_error("bb_opendir opendir");
    
//     fi->fh = (intptr_t) dp;
    
//     log_fi(fi);
    
//     return retstat;
// }


/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3ss
 */
int bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    DIR *dp = (DIR *) (uintptr_t) fi->fh;
    struct dirent *de;
    char meta_fpath[PATH_MAX];

    log_msg("\nbb_readdir(path=\"%s\", ...)\n", path);

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        char metadata_dir_fpath[PATH_MAX];
        bb_fullpath(metadata_dir_fpath, "/metadata/");
        snprintf(meta_fpath, PATH_MAX, "%s/%s", metadata_dir_fpath, de->d_name);

        json_t *root = load_metadata_json(meta_fpath);
        if (!root) continue;

        const char *orig_path_str = json_string_value(json_object_get(root, "path"));
        if (orig_path_str) {
            char *basec = strdup(orig_path_str);
            char *bname = basename(basec);
            filler(buf, bname, NULL, 0);
            free(basec);
        }
        json_decref(root);
    }

    return 0;
}

// int bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
// 	       struct fuse_file_info *fi)
// {
//     int retstat = 0;
//     DIR *dp;
//     struct dirent *de;
    
//     log_msg("\nbb_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
// 	    path, buf, filler, offset, fi);
//     // once again, no need for fullpath -- but note that I need to cast fi->fh
//     dp = (DIR *) (uintptr_t) fi->fh;

//     // Every directory contains at least two entries: . and ..  If my
//     // first call to the system readdir() returns NULL I've got an
//     // error; near as I can tell, that's the only condition under
//     // which I can get an error from readdir()
//     de = readdir(dp);
//     log_msg("    readdir returned 0x%p\n", de);
//     if (de == 0) {
// 	retstat = log_error("bb_readdir readdir");
// 	return retstat;
//     }

//     // This will copy the entire directory into the buffer.  The loop exits
//     // when either the system readdir() returns NULL, or filler()
//     // returns something non-zero.  The first case just means I've
//     // read the whole directory; the second means the buffer is full.
//     do {
// 	log_msg("calling filler with name %s\n", de->d_name);
// 	if (filler(buf, de->d_name, NULL, 0) != 0) {
// 	    log_msg("    ERROR bb_readdir filler:  buffer full");
// 	    return -ENOMEM;
// 	}
//     } while ((de = readdir(dp)) != NULL);
    
//     log_fi(fi);
    
//     return retstat;
// }

/** Release directory
 *
 * Introduced in version 2.3
 */
int bb_releasedir(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    log_msg("\nbb_releasedir(path=\"%s\", fi=0x%08x)\n",
	    path, fi);
    log_fi(fi);
    
    closedir((DIR *) (uintptr_t) fi->fh);
    
    return retstat;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
// when exactly is this called?  when a user calls fsync and it
// happens to be a directory? ??? >>> I need to implement this...
int bb_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    log_msg("\nbb_fsyncdir(path=\"%s\", datasync=%d, fi=0x%08x)\n",
	    path, datasync, fi);
    log_fi(fi);
    
    return retstat;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *bb_init(struct fuse_conn_info *conn)
{
    log_msg("\nbb_init()\n");
    
    log_conn(conn);
    log_fuse_context(fuse_get_context());
    
    // Construct the full paths for our internal directories
    char metadata_path[PATH_MAX];
    snprintf(metadata_path, PATH_MAX, "%s/metadata", BB_DATA->rootdir);

    char blocks_path[PATH_MAX];
    snprintf(blocks_path, PATH_MAX, "%s/blocks", BB_DATA->rootdir);

    //create hashes directory 
    char hashes_path[PATH_MAX];
    snprintf(hashes_path, PATH_MAX, "%s/hashes", BB_DATA->rootdir);
    
    // Create the directories. We don't care if they already exist.
    // The second argument to mkdir is the permissions mode. 0755 is standard.
    int retstat = mkdir(metadata_path, 0755);
    if (retstat < 0 && errno != EEXIST) {
        log_error("Failed to create metadata directory");
        //maybe return ERROR
    }
    log_msg(" -- Initialized metadata directory at %s\n", metadata_path);

    retstat = mkdir(blocks_path, 0755);
    if (retstat < 0 && errno != EEXIST) {
        log_error("Failed to create blocks directory");
        //maybe return ERROR
    }
    log_msg(" -- Initialized blocks directory at %s\n", blocks_path);

    retstat = mkdir(hashes_path, 0755);
    if (retstat < 0 && errno != EEXIST) {
        log_error("Failed to create blocks directory");
        //maybe return ERROR
    }
    log_msg(" -- Initialized blocks directory at %s\n", hashes_path);


    return BB_DATA;
}
/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
static void recursive_delete(const char* path) {
    DIR *dp = opendir(path);
    if (!dp) {
        log_error("recursive_delete opendir");
        return;
    }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            char full_path[PATH_MAX];
            snprintf(full_path, PATH_MAX, "%s/%s", path, de->d_name);
            
            struct stat statbuf;
            if (lstat(full_path, &statbuf) == 0) {
                if (S_ISDIR(statbuf.st_mode)) {
                    recursive_delete(full_path); // Recurse for subdirectories
                } else {
                    unlink(full_path); // Delete file
                }
            }
        }
    }
    closedir(dp);
    rmdir(path); // Delete the now-empty directory
}
void bb_destroy(void *userdata)
{
    log_msg("\nbb_destroy(userdata=0x%08x)\n", userdata);

    char path[PATH_MAX];
    struct stat st;

    log_msg(" -- Cleaning up storage directories\n");

    // Clear and remove the metadata directory if it exists
    snprintf(path, PATH_MAX, "%s/metadata", BB_DATA->rootdir);
    if (lstat(path, &st) == 0) {
        recursive_delete(path);
        log_msg("    bb_destroy: Cleaned up metadata directory.\n");
    }

    // Clear and remove the blocks directory if it exists
    snprintf(path, PATH_MAX, "%s/blocks", BB_DATA->rootdir);
    if (lstat(path, &st) == 0) {
        recursive_delete(path);
        log_msg("    bb_destroy: Cleaned up blocks directory.\n");
    }
    
    // Clear and remove the hashes directory if it exists
    snprintf(path, PATH_MAX, "%s/hashes", BB_DATA->rootdir);
    if (lstat(path, &st) == 0) {
        recursive_delete(path);
        log_msg("    bb_destroy: Cleaned up hashes directory.\n");
    }
}

// void bb_destroy(void *userdata)
// {
//     log_msg("\nbb_destroy(userdata=0x%08x)\n", userdata);

//     // char metadata_path[PATH_MAX];
//     // snprintf(metadata_path, PATH_MAX, "%s/metadata", BB_DATA->rootdir);

//     // char blocks_path[PATH_MAX];
//     // snprintf(blocks_path, PATH_MAX, "%s/blocks", BB_DATA->rootdir);

//     // log_msg(" -- Cleaning up directories\n");

//     // // 1. Clear all files inside the directories
//     // clear_directory(metadata_path);
//     // clear_directory(blocks_path);

//     // // 2. Remove the now-empty directories
//     // if (rmdir(metadata_path) < 0) {
//     //     log_error("bb_destroy rmdir metadata");
//     // }

//     // if (rmdir(blocks_path) < 0) {
//     //     log_error("bb_destroy rmdir blocks");
//     // }
// }
////////////////////////////////////////////////////////////////////////////////////////////////
// static void clear_directory(const char* dir_path) {
//     DIR *dp;
//     struct dirent *de;
//     char filepath[PATH_MAX];

//     dp = opendir(dir_path);
//     if (dp == NULL) {
//         log_error("clear_directory opendir");
//         return;
//     }

//     // Read every entry in the directory
//     while ((de = readdir(dp)) != NULL) {
//         // Skip the special '.' and '..' entries
//         if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
//             continue;
//         }

//         // Construct the full path to the file and delete it
//         snprintf(filepath, PATH_MAX, "%s/%s", dir_path, de->d_name);
//         if (unlink(filepath) < 0) {
//             log_error("clear_directory unlink");
//         }
//     }

//     closedir(dp);
// }
////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int bb_access(const char *path, int mask)
{
    int retstat = 0;
    char fpath[PATH_MAX];
   
    log_msg("\nbb_access(path=\"%s\", mask=0%o)\n",
	    path, mask);
    bb_fullpath(fpath, path);
    
    retstat = access(fpath, mask);
    
    if (retstat < 0)
	retstat = log_error("bb_access access");
    
    return retstat;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
// Not implemented.  I had a version that used creat() to create and
// open the file, which it turned out opened the file write-only.

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
int bb_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    log_msg("\nbb_ftruncate(path=\"%s\", offset=%lld, fi=0x%08x)\n",
	    path, offset, fi);
    log_fi(fi);
    
    retstat = ftruncate(fi->fh, offset);
    if (retstat < 0)
	retstat = log_error("bb_ftruncate ftruncate");
    
    return retstat;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
int bb_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    log_msg("\nbb_fgetattr(path=\"%s\", statbuf=0x%08x, fi=0x%08x)\n",
	    path, statbuf, fi);
    log_fi(fi);

    // On FreeBSD, trying to do anything with the mountpoint ends up
    // opening it, and then using the FD for an fgetattr.  So in the
    // special case of a path of "/", I need to do a getattr on the
    // underlying root directory instead of doing the fgetattr().
    if (!strcmp(path, "/"))
	return bb_getattr(path, statbuf);
    
    retstat = fstat(fi->fh, statbuf);
    if (retstat < 0)
	retstat = log_error("bb_fgetattr fstat");
    
    log_stat(statbuf);
    
    return retstat;
}

struct fuse_operations bb_oper = {
  .getattr = bb_getattr,
  .readlink = bb_readlink,
  // no .getdir -- that's deprecated
  .getdir = NULL,
  .mknod = bb_mknod,
  .mkdir = bb_mkdir,
  .unlink = bb_unlink,
  .rmdir = bb_rmdir,
  .symlink = bb_symlink,
  .rename = bb_rename,
  .link = bb_link,
  .chmod = bb_chmod,
  .chown = bb_chown,
  .truncate = bb_truncate,
  .utime = bb_utime,
  .open = bb_open,
  .read = bb_read,
  .write = bb_write,
  /** Just a placeholder, don't set */ // huh???
  .statfs = bb_statfs,
  .flush = bb_flush,
  .release = bb_release,
  .fsync = bb_fsync,
  
#ifdef HAVE_SYS_XATTR_H
  .setxattr = bb_setxattr,
  .getxattr = bb_getxattr,
  .listxattr = bb_listxattr,
  .removexattr = bb_removexattr,
#endif
  
  .opendir = bb_opendir,
  .readdir = bb_readdir,
  .releasedir = bb_releasedir,
  .fsyncdir = bb_fsyncdir,
  .init = bb_init,
  .destroy = bb_destroy,
  .access = bb_access,
  .ftruncate = bb_ftruncate,
  .fgetattr = bb_fgetattr
};

void bb_usage()
{
    fprintf(stderr, "usage:  bbfs [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main(int argc, char *argv[])
{
    int fuse_stat;
    struct bb_state *bb_data;

    // bbfs doesn't do any access checking on its own (the comment
    // blocks in fuse.h mention some of the functions that need
    // accesses checked -- but note there are other functions, like
    // chown(), that also need checking!).  Since running bbfs as root
    // will therefore open Metrodome-sized holes in the system
    // security, we'll check if root is trying to mount the filesystem
    // and refuse if it is.  The somewhat smaller hole of an ordinary
    // user doing it with the allow_other flag is still there because
    // I don't want to parse the options string.
    if ((getuid() == 0) || (geteuid() == 0)) {
    	fprintf(stderr, "Running BBFS as root opens unnacceptable security holes\n");
    	return 1;
    }

    // See which version of fuse we're running
    fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);
    
    // Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs)
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
	bb_usage();

    bb_data = malloc(sizeof(struct bb_state));
    if (bb_data == NULL) {
	perror("main calloc");
	abort();
    }

    // Pull the rootdir out of the argument list and save it in my
    // internal data
    bb_data->rootdir = realpath(argv[argc-2], NULL);
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
    
    bb_data->logfile = log_open();
    
    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
    
    return fuse_stat;
}
