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

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

static char doc[] = "OCI runtime";

static struct argp_option options[] = { { 0 } };

static char args_doc[] = "features";

const unsigned char *json_string;

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
add_string_to_json (yajl_gen json_gen, const char *key, char *value)
{
  yajl_gen_string (json_gen, (const unsigned char *) key, strlen (key));
  yajl_gen_string (json_gen, (const unsigned char *) value, strlen (value));
}

void
add_bool_to_json (yajl_gen json_gen, const char *key, int value)
{
  yajl_gen_string (json_gen, (const unsigned char *) key, strlen (key));
  yajl_gen_bool (json_gen, value);
}

void
add_bool_str_to_json (yajl_gen json_gen, const char *key, int value)
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

  yajl_gen_string (json_gen, (const unsigned char *) key, strlen (key));
  yajl_gen_string (json_gen, (const unsigned char *) val, strlen (val));
}

void
add_array_to_json (yajl_gen json_gen, const char *key, char **array)
{
  size_t i;
  yajl_gen_string (json_gen, (const unsigned char *) key, strlen (key));
  yajl_gen_array_open (json_gen);

  for (i = 0; array[i] != NULL; i++)
    yajl_gen_string (json_gen, (const unsigned char *) array[i], strlen (array[i]));

  yajl_gen_array_close (json_gen);
}

void
crun_features_add_hooks (yajl_gen json_gen, char **hooks)
{
  add_array_to_json (json_gen, "hooks", hooks);
}

void
crun_features_add_mount_options (yajl_gen json_gen, char **mount_options)
{
  add_array_to_json (json_gen, "mountOptions", mount_options);
}

void
crun_features_add_namespaces (yajl_gen json_gen, const struct linux_info_s *linux)
{
  add_array_to_json (json_gen, "namespaces", linux->namespaces);
}

void
crun_features_add_capabilities (yajl_gen json_gen, const struct linux_info_s *linux)
{
  add_array_to_json (json_gen, "capabilities", linux->capabilities);
}

void
crun_features_add_cgroup_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "cgroup", strlen ("cgroup"));
  yajl_gen_map_open (json_gen);

  add_bool_to_json (json_gen, "v1", linux->cgroup.v1);
  add_bool_to_json (json_gen, "v2", linux->cgroup.v2);
  add_bool_to_json (json_gen, "systemd", linux->cgroup.systemd);
  add_bool_to_json (json_gen, "systemdUser", linux->cgroup.systemd_user);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_seccomp_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "seccomp", strlen ("seccomp"));
  yajl_gen_map_open (json_gen);

  add_bool_to_json (json_gen, "enabled", linux->seccomp.enabled);
  if (linux->seccomp.actions)
    add_array_to_json (json_gen, "actions", linux->seccomp.actions);
  if (linux->seccomp.operators)
    add_array_to_json (json_gen, "operators", linux->seccomp.operators);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_mempolicy_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "memoryPolicy", strlen ("memoryPolicy"));
  yajl_gen_map_open (json_gen);

  if (linux->memory_policy.mode)
    add_array_to_json (json_gen, "modes", linux->memory_policy.mode);

  if (linux->memory_policy.flags)
    add_array_to_json (json_gen, "flags", linux->memory_policy.flags);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_apparmor_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "apparmor", strlen ("apparmor"));
  yajl_gen_map_open (json_gen);

  add_bool_to_json (json_gen, "enabled", linux->apparmor.enabled);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_selinux_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "selinux", strlen ("selinux"));
  yajl_gen_map_open (json_gen);

  add_bool_to_json (json_gen, "enabled", linux->selinux.enabled);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_mount_ext_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "mountExtensions", strlen ("mountExtensions"));
  yajl_gen_map_open (json_gen);

  yajl_gen_string (json_gen, (const unsigned char *) "idmap", strlen ("idmap"));
  yajl_gen_map_open (json_gen);
  add_bool_to_json (json_gen, "enabled", linux->mount_ext.idmap.enabled);
  yajl_gen_map_close (json_gen);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_intel_rdt (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "intelRdt", strlen ("intelRdt"));
  yajl_gen_map_open (json_gen);
  add_bool_to_json (json_gen, "enabled", linux->intel_rdt.enabled);
  yajl_gen_map_close (json_gen);
}

void
crun_features_add_net_devices (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "netDevices", strlen ("netDevices"));
  yajl_gen_map_open (json_gen);
  add_bool_to_json (json_gen, "enabled", linux->net_devices.enabled);
  yajl_gen_map_close (json_gen);
}

void
crun_features_add_linux_info (yajl_gen json_gen, const struct linux_info_s *linux)
{
  yajl_gen_string (json_gen, (const unsigned char *) "linux", strlen ("linux"));
  yajl_gen_map_open (json_gen);

  crun_features_add_namespaces (json_gen, linux);
  crun_features_add_capabilities (json_gen, linux);
  crun_features_add_cgroup_info (json_gen, linux);
  crun_features_add_seccomp_info (json_gen, linux);
  crun_features_add_apparmor_info (json_gen, linux);
  crun_features_add_selinux_info (json_gen, linux);
  crun_features_add_mount_ext_info (json_gen, linux);
  crun_features_add_intel_rdt (json_gen, linux);
  crun_features_add_net_devices (json_gen, linux);
  crun_features_add_mempolicy_info (json_gen, linux);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_annotations_info (yajl_gen json_gen, const struct annotations_info_s *annotation)
{
  yajl_gen_string (json_gen, (const unsigned char *) "annotations", strlen ("annotations"));
  yajl_gen_map_open (json_gen);

  if (! is_empty_string (annotation->io_github_seccomp_libseccomp_version))
    add_string_to_json (json_gen, "io.github.seccomp.libseccomp.version", annotation->io_github_seccomp_libseccomp_version);

  add_bool_str_to_json (json_gen, "org.opencontainers.runc.checkpoint.enabled", annotation->run_oci_crun_checkpoint_enabled);
  add_bool_str_to_json (json_gen, "run.oci.crun.checkpoint.enabled", annotation->run_oci_crun_checkpoint_enabled);

  add_string_to_json (json_gen, "run.oci.crun.commit", annotation->run_oci_crun_commit);
  add_string_to_json (json_gen, "run.oci.crun.version", annotation->run_oci_crun_version);

  add_bool_str_to_json (json_gen, "run.oci.crun.wasm", annotation->run_oci_crun_wasm);

  yajl_gen_map_close (json_gen);
}

void
crun_features_add_potentially_unsafe_config_annotations_info (yajl_gen json_gen, char **annotations)
{
  add_array_to_json (json_gen, "potentiallyUnsafeConfigAnnotations", annotations);
}

int
crun_command_features (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  cleanup_struct_features struct features_info_s *info = NULL;
  int first_arg = 0, ret = 0;
  libcrun_context_t crun_context = {
    0,
  };
  yajl_gen json_gen;

  argp_parse (&run_argp, argc, argv, 0, 0, &options);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Call the function in features.c to gather the feature information
  ret = libcrun_container_get_features (&crun_context, &info, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Prepare the JSON output
  json_gen = yajl_gen_alloc (NULL);
  if (json_gen == NULL)
    return libcrun_make_error (err, 0, "Failed to initialize json structure");

  yajl_gen_config (json_gen, yajl_gen_beautify, 1); // Optional: Enable pretty formatting

  // Start building the JSON
  yajl_gen_map_open (json_gen);

  // Add ociVersionMin field
  add_string_to_json (json_gen, "ociVersionMin", info->oci_version_min);

  // Add ociVersionMax field
  add_string_to_json (json_gen, "ociVersionMax", info->oci_version_max);

  // Add hooks array
  crun_features_add_hooks (json_gen, info->hooks);

  // Add mountOptions array
  crun_features_add_mount_options (json_gen, info->mount_options);

  // Add linux struct info
  crun_features_add_linux_info (json_gen, &info->linux);

  // Add annotations struct info
  crun_features_add_annotations_info (json_gen, &info->annotations);

  // Add potentially unsafe config annotatinos info
  crun_features_add_potentially_unsafe_config_annotations_info (json_gen, info->potentially_unsafe_annotations);

  // End building the JSON
  yajl_gen_map_close (json_gen);

  yajl_gen_get_buf (json_gen, &json_string, &json_length);

  printf ("%s", (const char *) json_string);

  yajl_gen_free (json_gen);

  return 0;
}
