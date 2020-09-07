#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/sysmacros.h>
#include <sys/param.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

#define TRACE_FILE "/tmp/kontain_crun_trace.out"
FILE *tracefile;

void
debug_open_tracefile (void)
{
  if (tracefile == NULL)
    {
      tracefile = fopen (TRACE_FILE, "a");
      if (tracefile == NULL)
        {
          abort ();
        }
    }
}

void
debug (char *fmt, ...)
{
  va_list ap;

  debug_open_tracefile ();
  va_start (ap, fmt);
  vfprintf (tracefile, fmt, ap);
  va_end (ap);
}

void
dumpmounts (libcrun_container_t *container)
{
  runtime_spec_schema_config_schema *container_def = container->container_def;
  size_t i;

  debug_open_tracefile ();

  for (i = 0; i < container_def->mounts_len; i++)
    {
      fprintf (tracefile, "mount[%zu]: source %s, destination %s, type %s, options_len %zu\n",
               i, container_def->mounts[i]->source, container_def->mounts[i]->destination,
               container_def->mounts[i]->type, container_def->mounts[i]->options_len);
      for (size_t j = 0; j < container_def->mounts[i]->options_len; j++)
        {
          fprintf (tracefile, "options[%zu]: %s\n", j, container_def->mounts[i]->options[j]);
        }
    }
  fflush (tracefile);
}

void
dumpdevices (libcrun_container_t *container)
{
  runtime_spec_schema_config_schema *container_def = container->container_def;

  debug_open_tracefile ();

  for (size_t i = 0; i < container_def->linux->devices_len; i++)
    {
      fprintf (tracefile, "devices[%zu]: type %s, path %s, "
                          "file_mode 0%o, file_mode_present %u, "
                          "major %" PRIu64 ", major_present %u, "
                          "minor %" PRIu64 ", minor_present %u, "
                          "uid %u, uid_present %u, "
                          "gid %u, gid_present %u\n",
               i,
               container_def->linux->devices[i]->type,
               container_def->linux->devices[i]->path,
               container_def->linux->devices[i]->file_mode,
               container_def->linux->devices[i]->file_mode_present,
               container_def->linux->devices[i]->major,
               container_def->linux->devices[i]->major_present,
               container_def->linux->devices[i]->minor,
               container_def->linux->devices[i]->minor_present,
               container_def->linux->devices[i]->uid,
               container_def->linux->devices[i]->uid_present,
               container_def->linux->devices[i]->gid,
               container_def->linux->devices[i]->gid_present);
    }
  fflush (tracefile);
}

void
dumpannotations (libcrun_container_t *container)
{
  runtime_spec_schema_config_schema *container_def = container->container_def;

  debug_open_tracefile ();

  fprintf (tracefile, "Begin annotations\n");
  if (container_def->annotations != NULL)
    {
      for (size_t i = 0; i < container_def->annotations->len; i++)
        {
          fprintf (tracefile, "%s = %s\n", container_def->annotations->keys[i], container_def->annotations->values[i]);
        }
    }
  fprintf (tracefile, "End annotations\n");

  fflush (tracefile);
}

void
dumpconfig (const char *config_file)
{
  FILE *config;
  char buffer[16 * 1024];

  config = fopen (config_file, "r");
  debug_open_tracefile ();

  fprintf (tracefile, "Begin %s\n", config_file);
  while (fgets (buffer, sizeof (buffer), config) != NULL)
    {
      fputs (buffer, tracefile);
    }
  fprintf (tracefile, "\nEnd %s\n", config_file);

  fclose (config);
  fflush (tracefile);
}

void
runtime_spec_to_file (runtime_spec_schema_config_schema *container)
{
  parser_error err;
  char *json_buf = NULL;

  json_buf = runtime_spec_schema_config_schema_generate_json (container, 0, &err);
  if (json_buf == NULL)
    {
      libcrun_fail_with_error (0, err);
      return;
    }

  debug_open_tracefile ();

  fputs (json_buf, tracefile);

  free (json_buf);
}

void
dump_crun_context (libcrun_context_t *context)
{
  char cwd[PATH_MAX];

  debug_open_tracefile ();
  getcwd (cwd, sizeof (cwd));
  fprintf (tracefile, "cwd %s\n", cwd);
  fprintf (tracefile, "state_root %s, id %s, bundle %s, config_file %s, pid_file %s, notify_socket %s\n",
           context->state_root, context->id, context->bundle, context->config_file, context->pid_file, context->notify_socket);
  fflush (tracefile);
}
