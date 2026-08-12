/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include "spec.h"
#include "utils.h"
#include "cgroup.h"
#include "cgroup-utils.h"

static const char spec_file[] = "\
{\n\
	\"ociVersion\": \"1.0.0\",\n\
	\"process\": {\n\
		\"terminal\": true,\n\
		\"user\": {\n\
			\"uid\": 0,\n\
			\"gid\": 0\n\
		},\n\
		\"args\": [\n\
			\"sh\"\n\
		],\n\
		\"env\": [\n\
			\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\n\
			\"TERM=xterm\"\n\
		],\n\
		\"cwd\": \"/\",\n\
		\"capabilities\": {\n\
			\"bounding\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"effective\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"inheritable\": [\n\
			],\n\
			\"permitted\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"ambient\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			]\n\
		},\n\
		\"rlimits\": [\n\
			{\n\
				\"type\": \"RLIMIT_NOFILE\",\n\
				\"hard\": 1024,\n\
				\"soft\": 1024\n\
			}\n\
		],\n\
		\"noNewPrivileges\": true\n\
	},\n\
	\"root\": {\n\
		\"path\": \"rootfs\",\n\
		\"readonly\": true\n\
	},\n\
	\"hostname\": \"crun\",\n\
	\"mounts\": [\n\
		{\n\
			\"destination\": \"/proc\",\n\
			\"type\": \"proc\",\n\
			\"source\": \"proc\"\n\
		},\n\
		{\n\
			\"destination\": \"/dev\",\n\
			\"type\": \"tmpfs\",\n\
			\"source\": \"tmpfs\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"strictatime\",\n\
				\"mode=755\",\n\
				\"size=65536k\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/pts\",\n\
			\"type\": \"devpts\",\n\
			\"source\": \"devpts\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"newinstance\",\n\
				\"ptmxmode=0666\",\n\
				\"mode=0620\"\
%s\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/shm\",\n\
			\"type\": \"tmpfs\",\n\
			\"source\": \"shm\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"mode=1777\",\n\
				\"size=65536k\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/mqueue\",\n\
			\"type\": \"mqueue\",\n\
			\"source\": \"mqueue\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/sys\",\n\
			\"type\": \"sysfs\",\n\
			\"source\": \"sysfs\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"ro\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/sys/fs/cgroup\",\n\
			\"type\": \"cgroup\",\n\
			\"source\": \"cgroup\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"relatime\",\n\
				\"ro\"\n\
			]\n\
		}\n\
	],\n\
	\"linux\": {\n\
		\"resources\": {\n\
			\"devices\": [\n\
				{\n\
					\"allow\": false,\n\
					\"access\": \"rwm\"\n\
				}\n\
			]\n\
		},\n\
		\"namespaces\": [\n\
			{\n\
				\"type\": \"pid\"\n\
			},\n\
			{\n\
				\"type\": \"network\"\n\
			},\n\
			{\n\
				\"type\": \"ipc\"\n\
			},\n\
			{\n\
				\"type\": \"uts\"\n\
			},\n\
%s\
%s\
			{\n\
				\"type\": \"mount\"\n\
			}\n\
		],\n\
		\"maskedPaths\": [\n\
			\"/proc/acpi\",\n\
			\"/proc/asound\",\n\
			\"/proc/kcore\",\n\
			\"/proc/keys\",\n\
			\"/proc/latency_stats\",\n\
			\"/proc/timer_list\",\n\
			\"/proc/timer_stats\",\n\
			\"/proc/sched_debug\",\n\
			\"/sys/firmware\",\n\
			\"/proc/scsi\"\n\
		],\n\
		\"readonlyPaths\": [\n\
			\"/proc/bus\",\n\
			\"/proc/fs\",\n\
			\"/proc/irq\",\n\
			\"/proc/sys\",\n\
			\"/proc/sysrq-trigger\"\n\
		]\n\
	}\n\
}\n";

static const char *spec_pts_tty_group = ",\n\
				\"gid=5\"\n";

static const char *spec_user = "\
			{\n\
				\"type\": \"user\"\n\
			},\n";

static const char *spec_cgroupns = "\
			{\n\
				\"type\": \"cgroup\"\n\
			},\n";

int
libcrun_container_spec (bool root, FILE *out, libcrun_error_t *err)
{
  int ret;
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  ret = fprintf (out, spec_file,
                 root ? spec_pts_tty_group : "\n",
                 root ? "" : spec_user,
                 cgroup_mode == CGROUP_MODE_UNIFIED ? spec_cgroupns : "");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fprintf failed");

  return ret;
}
