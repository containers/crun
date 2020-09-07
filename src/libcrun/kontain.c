/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Kontain Inc.
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "kontain.h"
#include "container.h"
#include "utils.h"

/*
 * If execpath is not a symlink to km or the path to km, then assume we
 * are to run execpath as a km payload.  In this case add km's path to argv[0]
 * and shift argv[0 ... n] up to argv[1 ... (n+1)] and return the absolute
 * path to km.
 * Arguments:
 *   argv[] is terminated with a null pointer.
 *   execpath - the program the caller wants to run, absolute path
 * Returns:
 *   0 - success
 *   errno - failure
 */
int libcrun_kontain_argv(char ***argv, const char **execpath)
{
   struct stat statb;
   char **newargv;
   const char *cmd = *execpath;

FILE *tf = fopen("/tmp/kontain_crun_trace.out", "a");
fprintf(tf, "%s: argv %p, execpath %p\n", __FUNCTION__, argv, execpath);
fflush(tf);
fprintf(tf, "execpath %p, %s\n", execpath, *execpath);
fflush(tf);
#if 1
for (int i = 0; (*argv)[i] != NULL; i++) {
  fprintf(tf, "argv[%d] = %s\n", i, (*argv)[i]);
  fflush(tf);
}
#endif
fprintf(tf, "done looking at argv[]\n");
fflush(tf);

fprintf(tf, "cmd %s\n", cmd);
fflush(tf);
   if (cmd[0] != '/') {  // verify that we are getting an absolute path
      return EINVAL;
   }
   if (fstatat(AT_FDCWD, cmd, &statb, AT_SYMLINK_NOFOLLOW) != 0) {
      // the command does not exist?  Let the caller handle that.
fprintf(tf, "stat(cmd) failed, errno %d\n", errno);
fflush(tf);
      return errno;
   }
fprintf(tf, "%s: st_mode 0%o\n", cmd, statb.st_mode);
fflush(tf);
   if ((statb.st_mode & S_IFMT) == S_IFLNK) {
      char linkcontents[PATH_MAX];
      while ((statb.st_mode & S_IFMT) == S_IFLNK) {
         int rc = readlink(cmd, linkcontents, sizeof(linkcontents));
fprintf(tf, "readlink %s returned %d\n", cmd, rc);
fflush(tf);
         if (rc < 0) {
            return errno;
         }
         linkcontents[rc] = 0;
         if (strcmp(linkcontents, KM_BIN_PATH) == 0) {
            // symlink to km, ok
            return 0;
         }
         if (fstatat(AT_FDCWD, linkcontents, &statb, AT_SYMLINK_NOFOLLOW) != 0) {
            return errno;
         }
         cmd = linkcontents;
      }
      // symlink to something other than km, stuff km in front of argv[0]
   } else if (strcmp(cmd, KM_BIN_PATH) == 0) {
      // The command is km, nothing more to do.
      return 0;
   }

   /* Some program other than km, assume they need km to run it so insert the path to km into argv[] */
   int argc;
   for (argc = 0; argv[argc] != NULL; argc++);
   argc++;  // for null array terminator

   // grow argv[]
   newargv = malloc((argc + 1) * sizeof(char*));
   if (newargv == NULL) {
      return ENOMEM;
   }

   // Set km to the program that is to be run, it will run the former argv[0]
   newargv[0] = strdup(KM_BIN_PATH);
   for (int i = 0; i <= argc; i++) {
      newargv[i + 1] = *argv[i];
   }

   // replace the payload filename and set the execpath to km's path
   free(newargv[1]);
   newargv[1] = (char *)*execpath;
   *execpath = strdup(KM_BIN_PATH);

   // Give the caller the new argv[]
   char **oldargv = *argv;
   *argv = newargv;
   free(oldargv);

fprintf(tf, "%s: done\n", __FUNCTION__);
   return 0;
}
