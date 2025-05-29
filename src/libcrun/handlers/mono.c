/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020, 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#define _GNU_SOURCE

#include <config.h>
#include "../custom-handler.h"
#include "../container.h"
#include "../utils.h"
#include "../linux.h"
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_MONO
#  include <mono/metadata/environment.h>
#  include <mono/utils/mono-publib.h>
#  include <mono/metadata/mono-config.h>
#  include <mono/jit/jit.h>
#endif

#if HAVE_DLOPEN && HAVE_MONO
static int
mono_exec (void *cookie arg_unused, libcrun_container_t *container arg_unused,
           const char *pathname, char *const argv[] arg_unused)
{
  MonoDomain *domain;
  char *path = (char *) pathname;
  int argc = 2;
  char *argv_mono[] = {
    path,
    path,
    NULL
  };
  const char *file;
  int retval;

  file = argv_mono[1];

  MonoAllocatorVTable mem_vtable = { MONO_ALLOCATOR_VTABLE_VERSION, xmalloc, NULL, NULL, NULL };
  mono_set_allocator_vtable (&mem_vtable);

  /*
   * Load the default Mono configuration file, this is needed
   * if you are planning on using the dllmaps defined on the
   * system configuration
   */
  mono_config_parse (NULL);
  /*
   * mono_jit_init() creates a domain: each assembly is
   * loaded and run in a MonoDomain.
   */
  domain = mono_jit_init (file);

  /*
   * We add our special internal call, so that C# code
   * can call us back.
   */

  MonoAssembly *assembly;
  assembly = mono_domain_assembly_open (domain, file);
  if (! assembly)
    exit (EXIT_FAILURE);
  /*
   * mono_jit_exec() will run the Main() method in the assembly.
   * The return value needs to be looked up from
   * System.Environment.ExitCode.
   */
  mono_jit_exec (domain, assembly, argc - 1, argv_mono + 1);
  retval = mono_environment_exitcode_get ();
  mono_jit_cleanup (domain);
  return 0;
}

static int
mono_load (void **cookie, libcrun_error_t *err)
{
  void *handle;

  handle = dlopen ("libmono-native.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libmono-native.so`: `%s`", dlerror ());
  *cookie = handle;

  return 0;
}

static int
mono_configure_container (void *cookie arg_unused, enum handler_configure_phase phase,
                          libcrun_context_t *context arg_unused, libcrun_container_t *container,
                          const char *rootfs arg_unused, libcrun_error_t *err)
{
  int ret;
  if (phase != HANDLER_CONFIGURE_MOUNTS)
    return 0;

  char *options[] = {
    "ro",
    "rprivate",
    "nosuid",
    "nodev",
    "rbind"
  };

  ret = libcrun_container_do_bind_mount (container, "/etc/mono", "/etc/mono", options, 5, err);
  if (ret != 0)
    return ret;

  ret = libcrun_container_do_bind_mount (container, "/usr/lib/mono", "/usr/lib/mono", options, 5, err);
  if (ret != 0)
    return ret;

  return 0;
}

static int
mono_unload (void *cookie, libcrun_error_t *err)
{
  int r;

  if (cookie)
    {
      r = dlclose (cookie);
      if (UNLIKELY (r < 0))
        return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
    }
  return 0;
}

static int
mono_can_handle_container (libcrun_container_t *container, libcrun_error_t *err arg_unused)
{
  const char *annotation;

  annotation = find_annotation (container, "run.oci.handler");
  if (annotation)
    return strcmp (annotation, "dotnet") == 0 ? 1 : 0;

  return 0;
}

struct custom_handler_s handler_mono = {
  .name = "dotnet",
  .alias = NULL,
  .feature_string = ".NET:mono",
  .load = mono_load,
  .unload = mono_unload,
  .run_func = mono_exec,
  .can_handle_container = mono_can_handle_container,
  .configure_container = mono_configure_container,
};

#endif
