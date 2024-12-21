/*
 * crun - OCI runtime written in C
 *
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
#include "libcrun/container.h"
#include "libcrun/utils.h"

static char doc[] = "OCI runtime";

static struct argp_option options[] = { { 0 } };

static char args_doc[] = "features";

char *content_string;

size_t json_length;

static error_t
parse_opt (int key, char *arg arg_unused, struct argp_state *state arg_unused)
{
  if (key != ARGP_KEY_NO_ARGS)
    {
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

void
add_string_to_json (json_t *root, const char *key, char *value)
{
  json_object_set (root, key, json_string (value));
}

void
add_bool_to_json (json_t *root, const char *key, int value)
{
  json_object_set (root, key, json_boolean (value));
}

void
add_bool_str_to_json (json_t *root, const char *key, int value)
{
  char *val = "";
  if (value)
    {
      val = "true";
    }
  else
    {
      val = "false";
    }
  json_object_set (root, key, json_string (val));
}

void
add_array_to_json (json_t *root, const char *key, char **array)
{
  size_t i;
  json_t *obj = json_array ();

  for (i = 0; array[i] != NULL; i++)
    json_array_append (obj, json_string (array[i]));

  json_object_set (root, key, obj);
}

void
crun_features_add_hooks (json_t *root, char **hooks)
{
  add_array_to_json (root, "hooks", hooks);
}

void
crun_features_add_mount_options (json_t *root, char **mount_options)
{
  add_array_to_json (root, "mountOptions", mount_options);
}

void
crun_features_add_namespaces (json_t *root, const struct linux_info_s *linux)
{
  add_array_to_json (root, "namespaces", linux->namespaces);
}

void
crun_features_add_capabilities (json_t *root, const struct linux_info_s *linux)
{
  add_array_to_json (root, "capabilities", linux->capabilities);
}

void
crun_features_add_cgroup_info (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();
  add_bool_to_json (obj, "v1", linux->cgroup.v1);
  add_bool_to_json (obj, "v2", linux->cgroup.v2);
  add_bool_to_json (obj, "systemd", linux->cgroup.systemd);
  add_bool_to_json (obj, "systemdUser", linux->cgroup.systemd_user);

  json_object_set (root, (const char *) "cgroup", obj);
}

void
crun_features_add_seccomp_info (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();

  add_bool_to_json (obj, "enabled", linux->seccomp.enabled);
  if (linux->seccomp.actions)
    add_array_to_json (obj, "actions", linux->seccomp.actions);
  if (linux->seccomp.operators)
    add_array_to_json (obj, "operators", linux->seccomp.operators);

  json_object_set (root, (const char *) "seccomp", obj);
}

void
crun_features_add_apparmor_info (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();

  add_bool_to_json (obj, "enabled", linux->apparmor.enabled);

  json_object_set (root, (const char *) "apparmor", obj);
}

void
crun_features_add_selinux_info (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();

  add_bool_to_json (obj, "enabled", linux->selinux.enabled);

  json_object_set (root, (const char *) "selinux", obj);
}

void
crun_features_add_mount_ext_info (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();
  json_t *subobj = json_object ();
  add_bool_to_json (subobj, "enabled", linux->mount_ext.idmap.enabled);
  json_object_set (obj, (const char *) "idmap", subobj);
  json_object_set (root, (const char *) "mountExtensions", obj);
}

void
crun_features_add_intel_rdt (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();
  add_bool_to_json (obj, "enabled", linux->intel_rdt.enabled);
  json_object_set (root, (const char *) "intelRdt", obj);
}

void
crun_features_add_linux_info (json_t *root, const struct linux_info_s *linux)
{
  json_t *obj = json_object ();

  crun_features_add_namespaces (obj, linux);
  crun_features_add_capabilities (obj, linux);
  crun_features_add_cgroup_info (obj, linux);
  crun_features_add_seccomp_info (obj, linux);
  crun_features_add_apparmor_info (obj, linux);
  crun_features_add_selinux_info (obj, linux);
  crun_features_add_mount_ext_info (obj, linux);
  crun_features_add_intel_rdt (obj, linux);

  json_object_set (root, (const char *) "linux", obj);
}

void
crun_features_add_annotations_info (json_t *root, const struct annotations_info_s *annotation)
{
  json_t *obj = json_object ();

  if (! is_empty_string (annotation->io_github_seccomp_libseccomp_version))
    add_string_to_json (obj, "io.github.seccomp.libseccomp.version", annotation->io_github_seccomp_libseccomp_version);

  add_bool_str_to_json (obj, "org.opencontainers.runc.checkpoint.enabled", annotation->run_oci_crun_checkpoint_enabled);
  add_bool_str_to_json (obj, "run.oci.crun.checkpoint.enabled", annotation->run_oci_crun_checkpoint_enabled);

  add_string_to_json (obj, "run.oci.crun.commit", annotation->run_oci_crun_commit);
  add_string_to_json (obj, "run.oci.crun.version", annotation->run_oci_crun_version);

  add_bool_str_to_json (obj, "run.oci.crun.wasm", annotation->run_oci_crun_wasm);

  json_object_set (root, (const char *) "annotations", obj);
}

void
crun_features_add_potentially_unsafe_config_annotations_info (json_t *root, char **annotations)
{
  add_array_to_json (root, "potentiallyUnsafeConfigAnnotations", annotations);
}

int
crun_command_features (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  cleanup_struct_features struct features_info_s *info = NULL;
  int first_arg = 0, ret = 0;
  libcrun_context_t crun_context = {
    0,
  };
  json_t *root = json_object ();

  argp_parse (&run_argp, argc, argv, 0, 0, &options);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Call the function in features.c to gather the feature information
  ret = libcrun_container_get_features (&crun_context, &info, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Add ociVersionMin field
  add_string_to_json (root, "ociVersionMin", info->oci_version_min);

  // Add ociVersionMax field
  add_string_to_json (root, "ociVersionMax", info->oci_version_max);

  // Add hooks array
  crun_features_add_hooks (root, info->hooks);

  // Add mountOptions array
  crun_features_add_mount_options (root, info->mount_options);

  // Add linux struct info
  crun_features_add_linux_info (root, &info->linux);

  // Add annotations struct info
  crun_features_add_annotations_info (root, &info->annotations);

  // Add potentially unsafe config annotatinos info
  crun_features_add_potentially_unsafe_config_annotations_info (root, info->potentially_unsafe_annotations);

  content_string = json_dumps (root, JSON_INDENT (2));

  printf ("%s", content_string);

  // decrement reference
  json_decref (root);

  // free content_string;
  free (content_string);

  return 0;
}
