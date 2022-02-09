/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020-2021 Kontain Inc.
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

#include "container.h"
#include "utils.h"
#include "kontain.h"

int 
libcrun_kontain_use_argv(libcrun_context_t *context, libcrun_container_t *container)
{
  if (context->kontain == 0)
    {
      return 0;
    }
  if (context->kontain_ecs == 0)
    {
      return 1;
    }
  const char *label = find_annotation (container, "app.kontain.version");
  if (label != NULL && strcmp(label, "1") == 0)
    {
      return 1;
    }
  return 0;
}

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
int
libcrun_kontain_argv (char ***argv, char **execpath)
{
  struct stat statb;
  char **newargv;
  const char *cmd = *execpath;

  if (cmd[0] != '/')
    { // verify that we are getting an absolute path
      return EINVAL;
    }
  if (fstatat (AT_FDCWD, cmd, &statb, AT_SYMLINK_NOFOLLOW) != 0)
    {
      // the command does not exist?  Let the caller handle that.
      return errno;
    }
  if (strcmp (cmd, KM_BIN_PATH) != 0)
    {
      /* Some program other than km, assume they need km to run it so insert the path to km into argv[] */
      int argc;
      for (argc = 0; (*argv)[argc] != NULL; argc++)
        ;
      argc++; // for null array terminator

      // grow argv[]
      newargv = malloc ((argc + 1) * sizeof (char *));
      if (newargv == NULL)
        {
          return ENOMEM;
        }

      // Set km to the program that is to be run, it will run the former argv[0]
      newargv[0] = strdup (KM_BIN_PATH);
      for (int i = 0; i < argc; i++)
        {
          newargv[i + 1] = (*argv)[i];
        }

      // replace the payload filename and set the execpath to km's path
      free (newargv[1]);
      newargv[1] = (char *) strdup (*execpath);
      *execpath = strdup (KM_BIN_PATH);

      // Give the caller the new argv[]
      char **oldargv = *argv;
      *argv = newargv;
      free (oldargv);
    }

  /*
   * If docker or podman run was invoked with --init then the actual entrypoint may
   * may be further in the argument list and may already have /opt/kontain/bin/km
   * in the argument list.  We need to remove the /opt/kontain/bin/km argument in
   * this case.  These are the argument lists we would expect to see after the above
   * code has added km as argv[0].
   * docker:
   *  /opt/kontain/bin/km /sbin/docker-init -- /opt/kontain/bin/km /bin/sh
   * podman:
   *  /opt/kontain/bin/km /dev/init -- /opt/kontain/bin/km /bin/sh
   */
  if ((strcmp ((*argv)[1], DOCKER_INIT_PATH) == 0 || strcmp ((*argv)[1], PODMAN_INIT_PATH) == 0) && strcmp ((*argv)[3], KM_BIN_PATH) == 0)
    {
      char *avoid_maintmk_warning = (*argv)[3];
      free (avoid_maintmk_warning);
      for (int i = 3; (*argv)[i] != NULL; i++)
        {
          (*argv)[i] = (*argv)[i + 1];
        }
    }

  return 0;
}
