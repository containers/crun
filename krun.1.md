crun 1 "User Commands"
==================================================

# NAME

krun - crun based OCI runtime using libkrun to run containerized programs in
isolated KVM environments

# SYNOPSIS

krun [global options] command [command options] [arguments...]

# DESCRIPTION

krun is a sub package of the crun command line program for running Linux
containers that follow the Open Container Initiative (OCI) format. The krun
command is a symbolic link to the crun executable, that tells crun to run in
krun mode.

krun uses the dynamic libkrun library to run processes in an isolated
environment using KVM Virtualization.

libkrun integrates a VMM (Virtual Machine Monitor, the userspace side of a
Hypervisor) with the minimum amount of emulated devices required for its
purpose, abstracting most of the complexity from Virtual Machine management.

Because of the additional isolation, sharing content with processes and other
containers outside of the krun VM is more difficult.

# CONFIGURATION

The microVM can be configured through OCI annotations or a
**.krun_vm.json** file placed at the root of the container image.
When both are present, OCI annotations take precedence.

## OCI Annotations

OCI annotations can be passed at container creation time. For
example, with podman:

    podman run --runtime=krun --annotation krun.nested_virt=1 ...

The following annotations are supported:

**krun.cpus**=*NUM*
:   Number of vCPUs for the microVM (maximum 16). If not set, defaults
    to the number of CPUs available via the process CPU affinity.

**krun.ram_mib**=*NUM*
:   Amount of RAM in MiB for the microVM. Values below 128 MiB are
    ignored. If not set, defaults to the OCI memory limit if present,
    otherwise 1024 MiB.

**krun.gpu_flags**=*FLAGS*
:   Enable virtio-gpu with the specified virgl flags. Requires
    **/dev/dri** to be available. When *FLAGS* includes
    **VIRGLRENDERER_RENDER_SERVER**, **/usr/libexec/virgl_render_server**
    must also be available.

**krun.use_passt**=*NUM*
:   When set to a value greater than 0, enable passt-based networking
    in the microVM.

**krun.tap_name**=*NAME*
:   Attach the microVM to an existing TAP interface *NAME* through a
    virtio-net device, disabling the default TSI (Transparent Socket
    Impersonation) networking. Requires a libkrun built with
    virtio-net support. This option is mutually exclusive with
    **krun.use_passt**.

**krun.nested_virt**=*NUM*
:   When set to a value greater than 0, enable nested virtualization
    in the microVM, exposing hardware virtualization support (VMX on
    Intel, SVM on AMD) to the guest. This requires nested
    virtualization to be enabled on the host (e.g.
    **/sys/module/kvm_intel/parameters/nested** or
    **/sys/module/kvm_amd/parameters/nested** must report **Y** or
    **1**). A warning is emitted if the host does not appear to
    support nested virtualization.

**krun.custom_kernel**=*NUM*
:   When set to a value greater than 0, allow the VM configuration
    file to specify a custom kernel via the **kernel_path**,
    **kernel_format**, **initrd_path**, and **kernel_cmdline** fields.

**krun.variant**=*VARIANT*
:   Select an alternative libkrun variant. Supported values are
    **sev** (AMD SEV confidential workloads) and **aws-nitro** (AWS
    Nitro Enclaves).

## VM Configuration File

A **.krun_vm.json** file can be placed at the root of the container
image to provide default VM settings. The file is a JSON object with
the following optional fields:

- **cpus** (integer): same as the **krun.cpus** annotation.
- **ram_mib** (integer): same as the **krun.ram_mib** annotation.
- **kernel_path** (string): path to an external kernel. Requires the
  **krun.custom_kernel** annotation.
- **kernel_format** (integer): kernel format identifier. Requires the
  **krun.custom_kernel** annotation.
- **initrd_path** (string): path to an initrd image. Requires the
  **krun.custom_kernel** annotation.
- **kernel_cmdline** (string): kernel command line. Requires the
  **krun.custom_kernel** annotation.
- **virtiofs_tag** (string): VirtioFS tag (defaults to **/dev/root**).
- **virtiofs_shm_size** (integer): VirtioFS DAX shared memory size in
  bytes (defaults to 512 MiB).
- **virtiofs** (array): additional VirtioFS devices, added in order
  after the root device. Each entry is an object containing a unique
  **tag** of at most 36 bytes, an absolute **path** inside the
  container, and a positive **shm_size** in bytes.

The following options are only available through OCI annotations and
are not read from the configuration file: **gpu_flags**,
**use_passt**, **tap_name**, **nested_virt**, and **flavor**.

Example:

    {
      "cpus": 4,
      "ram_mib": 2048,
      "virtiofs": [
        {"tag": "devshm", "path": "/dev/shm", "shm_size": 536870912}
      ]
    }

# COMMANDS

See crun.1 man page for the commands available to krun

# SEE ALSO
crun.1
