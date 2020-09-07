/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020-2021 Kontain Inc.
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_BSD_QUEUE
#  include <bsd/sys/queue.h>
#else
#  include <sys/queue.h>
#endif
#include <regex.h>
#include <stdlib.h>
#include <errno.h>
#include "utils.h"
#include <openssl/evp.h>

/*
 * Sometimes we need to allow programs to be run outside of kontain's vm encapsulation.
 * But, we don't want arbitrary programs to be run this way.  So, we have a list of acceptable
 * programs that "docker exec ...." should be able to run.  This list is stored in
 * file (see KONTAIN_KRUN_CONFIG definition below).  When it is time to do the
 * exec() system call we parse the config file, check to see if the program we are execing
 * is allowed to run without vm encapsulation.  If it is allowed we exec the program directly.
 * If not, the program will need to run within a km virtual machine.
 * This blob of code is just used to see if a program should be allowed to run without
 * km containment.  The caller of libcrun_kontain_nonkmexec_allowed() uses the returned
 * information to form the appropriate exec arguments.
 */

struct execpath_entry
{
  SLIST_ENTRY (execpath_entry)
  link;
  regex_t re;
  char *path;
  char sha256[EVP_MAX_MD_SIZE * 2 + 1];
};
typedef struct execpath_entry execpath_entry_t;

SLIST_HEAD (execpath_head, execpath_entry);
typedef struct execpath_head execpath_head_t;

struct execpath_state
{
  pthread_mutex_t execpath_mutex; // do we need this?
  execpath_head_t execpath_head;
  char *execpath_dbpath;          // the path we read to populate the execpath_head
  struct timespec execpath_mtime; // dbpath mtime when the file was read
};
typedef struct execpath_state execpath_state_t;

#define KONTAIN_KRUN_CONFIG "/var/lib/krun/config"

execpath_state_t execpath_state = {
  PTHREAD_MUTEX_INITIALIZER, SLIST_HEAD_INITIALIZER (&execpath_state.execpath_head), KONTAIN_KRUN_CONFIG, { 0, 0 }
};

static void
kontain_execpath_freedb (execpath_state_t *statep)
{
  execpath_entry_t *epp;

  while (! SLIST_EMPTY (&statep->execpath_head))
    {
      epp = SLIST_FIRST (&statep->execpath_head);
      SLIST_REMOVE_HEAD (&statep->execpath_head, link);
      free (epp->path);
      regfree (&epp->re);
      free (epp);
    }
  memset (&statep->execpath_mtime, 0, sizeof (statep->execpath_mtime));
}

// Destroy the execpath ok db.
void
libcrun_kontain_nonkmexec_clean (void)
{
  kontain_execpath_freedb (&execpath_state);
}

static void
hash_2_ascii (unsigned char hash[EVP_MAX_MD_SIZE], unsigned int hash_len, char *ascii)
{
  unsigned int i;
  for (i = 0; i < hash_len; i++)
    {
      snprintf (&ascii[i * 2], 3, "%02x", hash[i]);
    }
  ascii[i * 2] = 0;
}

/*
 * Compute the sha256 hash of the passed file.
 * Return the hash in ascii in returned_hash.
 * Returns:
 *   0 - success
 *   != 0 - an errno value describing what failed
 */
static int
sha256_file (char *file, char *returned_hash)
{
  int f;
  unsigned char filebuf[128 * 1024];
  EVP_MD_CTX *ctx;
  unsigned char final_hash[EVP_MAX_MD_SIZE];
  unsigned int final_hash_len;
  ssize_t bytesread;

  f = open (file, O_RDONLY);
  if (f < 0)
    {
      return errno;
    }

  ctx = EVP_MD_CTX_new ();
  EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL);
  while ((bytesread = read (f, filebuf, sizeof (filebuf))) > 0)
    {
      EVP_DigestUpdate (ctx, filebuf, bytesread);
    }
  close (f);
  if (bytesread < 0)
    {
      EVP_MD_CTX_free (ctx);
      return errno;
    }
  EVP_DigestFinal_ex (ctx, final_hash, &final_hash_len);
  EVP_MD_CTX_free (ctx);
  hash_2_ascii (final_hash, final_hash_len, returned_hash);
  return 0;
}

// Split a line from the exec ok file into its fields
static int
split_into_fields (char *dbentry, char *fields[])
{
  char *saveptr = NULL;

  fields[0] = strtok_r (dbentry, ":", &saveptr);
  if (fields[0] == NULL)
    {
      return EINVAL;
    }
  fields[1] = strtok_r (NULL, ":", &saveptr);
  if (fields[0] == NULL)
    {
      return EINVAL;
    }
  fields[2] = strtok_r (NULL, ":", &saveptr);
  if (fields[2] == NULL)
    {
      return EINVAL;
    }
  return 0;
}

/*
 * Read a execpath database and place it into execpath_state_t pointed to by statep.
 * Entries in the file are a single line with fields separated by colons.
 * There are 3 fields:
 *   regular expression to match an input string against
 *   the file to exec to if the regular expression matches
 *   the sha of the file being exec'ed to verify the file is unchanged since the
 *   db was created.
 * Example of a line in the file:
 *   /bin/ping|/usr/bin/ping:/bin/ping:XXXXXX
 * Where XXXXXX is the sha256 of the file /bin/ping.
 * Failures is this function cause the process to exit.
 *
 * We should probably use some sort of json representation for this instead of the
 * archaic colon separated fields.
 */
static void
kontain_execpath_builddb (execpath_state_t *statep)
{
  char buf[1024];
  FILE *f = NULL;
  char *fields[3];
  execpath_entry_t *epp = NULL;
  execpath_entry_t *tail = NULL;
  int rc = 0;

  kontain_execpath_freedb (statep);
  f = fopen (statep->execpath_dbpath, "r");
  if (f == NULL)
    {
      libcrun_fail_with_error (errno, "Couldn't open %s", statep->execpath_dbpath);
    }
  buf[sizeof (buf) - 1] = 0;
  while (fgets (buf, sizeof (buf), f) != NULL)
    {
      if (buf[sizeof (buf) - 1] != 0)
        {
          // a really long line.
          rc = E2BIG;
          buf[sizeof (buf) - 1] = 0;
          libcrun_fail_with_error (rc, "line: %s in %s is too long: %s", buf, statep->execpath_dbpath);
        }
      if (buf[0] == '#')
        { // ignore comments
          continue;
        }
      char *s = strchr (buf, '\n');
      if (s != NULL)
        {
          *s = 0;
        }
      // Split into fields
      if (split_into_fields (buf, fields) != 0)
        {
          rc = EINVAL;
          libcrun_fail_with_error (rc, "Couldn't split <%s> into fields", buf);
        }

      epp = calloc (sizeof (execpath_entry_t), 1);
      if (epp == NULL)
        {
          libcrun_fail_with_error (ENOMEM, "Couldn't allocate %d bytes of memory", sizeof (execpath_entry_t));
        }

      // Compile regular expression.
      rc = regcomp (&epp->re, fields[0], REG_EXTENDED | REG_NOSUB);
      if (rc != 0)
        {
          char regerrbuf[128];
          regerror (rc, &epp->re, regerrbuf, sizeof (regerrbuf));
          libcrun_fail_with_error (rc, "Couldn't compile regular expression %s, %s", fields[0], regerrbuf);
        }
      epp->path = strdup (fields[1]);
      if (epp->path == NULL)
        {
          rc = ENOMEM;
          libcrun_fail_with_error (rc, "Couldn't strdup %s", fields[1]);
        }

      // Compute hash of target file
      rc = sha256_file (fields[1], epp->sha256);
      if (rc != 0)
        {
          libcrun_fail_with_error (rc, "Couldn't compute hash of file %s", fields[1]);
        }
      // Does the hash match what the exec_ok file has?
      if (strcmp (epp->sha256, fields[2]) != 0)
        {
          printf ("%s: Computed hash %s doesn't match expected hash %s\n", fields[1], epp->sha256, fields[2]);
          libcrun_fail_with_error (EILSEQ, "hash on file %s differ: expected: %s got: %s", epp->path, fields[2],
                                   epp->sha256);
        }

      // Chain entry on to the end of the list
      libcrun_warning ("Adding nonkm path: %s, %s, %s", fields[0], fields[1], fields[2]);
      if (tail == NULL)
        {
          SLIST_INSERT_HEAD (&statep->execpath_head, epp, link);
        }
      else
        {
          SLIST_INSERT_AFTER (tail, epp, link);
        }
      tail = epp;
      epp = NULL;
    }
  fclose (f);

  // Remember the file's mod time
  struct stat statb;
  rc = stat (statep->execpath_dbpath, &statb);
  if (rc == 0)
    {
      statep->execpath_mtime = statb.st_mtim;
    }
  else
    {
      libcrun_fail_with_error (errno, "stat %s failed", statep->execpath_dbpath);
    }
}

// Find an entry in the execpath_ok db that matches execpath.
static int
kontain_execpath_lookup (execpath_state_t *statep, const char *execpath, execpath_entry_t **eppp)
{
  struct stat statb;

  if (stat (statep->execpath_dbpath, &statb) != 0)
    {
      if (errno != ENOENT)
        {
          libcrun_warning ("%s: can't access %s, error %s", __FUNCTION__, statep->execpath_dbpath, strerror (errno));
          return errno;
        }
      // No allowed executable file, so no executable is allowed to run without km
      *eppp = NULL;
      return 0;
    }
  if (memcmp (&statb.st_mtim, &statep->execpath_mtime, sizeof (struct timespec)) != 0)
    {
      kontain_execpath_builddb (statep);
    }

  execpath_entry_t *epp;
  SLIST_FOREACH (epp, &statep->execpath_head, link)
  {
    if (regexec (&epp->re, execpath, 0, NULL, 0) == 0)
      {
        // this entry matches
        *eppp = epp;
        return 0;
      }
  }
  *eppp = NULL;
  return 0;
}

/*
 * Given a full path to an executable that we want to pass to exec, verify that
 * the path is allowed by looking up the path in a database.  Once a matching
 * entry is found, take the path that should be used from the entry, then verify
 * that the executable is the one we expect, and finally return that path to the
 * caller.
 * Returns:
 *   0 - the check succeeded, the value returned in execpath_allowed is valid.
 *   != 0 - the check failed, the value returned in execpath_allowed is meaningless.
 * execpath_allowed - returns the path the caller can exec to.  If the returned
 *   pointer is null, they can't exec directly to the path passed in execpath.
 */
int
libcrun_kontain_nonkmexec_allowed (const char *execpath, char **execpath_allowed)
{
  execpath_entry_t *epp;

  // lookup up execpath
  int rc = kontain_execpath_lookup (&execpath_state, execpath, &epp);
  if (rc != 0)
    {
      return rc;
    }
  if (epp == NULL)
    {
      // no matching entry, they can't run without km.
      *execpath_allowed = NULL;
      return 0;
    }

  // Compute sha of associated path
  char file_sha[2 * EVP_MAX_MD_SIZE + 1];
  if ((rc = sha256_file (epp->path, file_sha)) != 0)
    {
      libcrun_fail_with_error (rc, "Couldn't compute hash for file %s", epp->path);
    }

  // If computed sha doesn't match sha in matched entry, fail
  if (strcmp (file_sha, epp->sha256) != 0)
    {
      libcrun_fail_with_error (EACCES, "hashs differ %s - %s", file_sha, epp->sha256);
    }

  // Return matched path.
  *execpath_allowed = strdup (epp->path);
  if (*execpath_allowed == NULL)
    {
      libcrun_fail_with_error (ENOMEM, "Couldn't strdup %s", *execpath_allowed);
    }
  return 0;
}
