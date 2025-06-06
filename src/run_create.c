/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <unistd.h>
#include <errno.h>

#include "crun.h"
#include "run_create.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

int
crun_run_create_internal (struct crun_global_arguments *global_args, int argc, char **argv,
                          container_run_create_func_t container_run_create_func, get_options_func_t get_options_func,
                          libcrun_context_t *crun_context, struct argp *run_argp, const char **config_file_ptr,
                          const char **bundle_ptr, libcrun_error_t *err)
{
  int first_arg = 0, ret;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_free char *bundle_cleanup = NULL;
  cleanup_free char *config_file_cleanup = NULL;

  crun_context->preserve_fds = 0;
  crun_context->listen_fds = 0;

  argp_parse (run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, crun_context);
  /* Get options after parsing the arguments.  */
  unsigned int options = get_options_func ();
  const char *config_file = *config_file_ptr;
  const char *bundle = *bundle_ptr;

  crun_assert_n_args (argc - first_arg, 1, 1);

  /* Make sure the config is an absolute path before changing the directory.  */
  if ((strcmp ("config.json", config_file) != 0))
    {
      if (config_file[0] != '/')
        {
          config_file_cleanup = realpath (config_file, NULL);
          if (config_file_cleanup == NULL)
            libcrun_fail_with_error (errno, "realpath `%s` failed", config_file);
          config_file = config_file_cleanup;
        }
    }

  /* Make sure the bundle is an absolute path.  */
  if (bundle == NULL)
    {
      bundle = bundle_cleanup = getcwd (NULL, 0);
      if (UNLIKELY (bundle == NULL))
        libcrun_fail_with_error (errno, "getcwd failed");
    }
  else
    {
      if (bundle[0] != '/')
        {
          bundle_cleanup = realpath (bundle, NULL);
          if (bundle_cleanup == NULL)
            libcrun_fail_with_error (errno, "realpath `%s` failed", bundle);
          bundle = bundle_cleanup;
        }

      if (chdir (bundle) < 0)
        libcrun_fail_with_error (errno, "chdir `%s` failed", bundle);
    }

  ret = init_libcrun_context (crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  container = libcrun_container_load_from_file (config_file, err);
  if (container == NULL)
    return -1;

  libcrun_debug ("Using bundle: %s", bundle);
  crun_context->bundle = bundle;
  if (getenv ("LISTEN_FDS"))
    {
      crun_context->listen_fds = parse_int_or_fail (getenv ("LISTEN_FDS"), "LISTEN_FDS");
      crun_context->preserve_fds += crun_context->listen_fds;
    }
  return container_run_create_func (crun_context, container, options, err);
}
