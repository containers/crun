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

# ARCHITECTURE

krun operates by first setting up a standard OCI container namespace and
cgroup configuration using crun's normal container setup code. Once the
container environment is prepared, crun invokes libkrun to launch a
microVM. The workload inside the container then runs within this microVM
rather than directly on the host kernel.

The architecture consists of three main components:

1. **crun**: Sets up the container namespaces (user, pid, mount, ipc, uts, cgroup),
   mounts the root file system, and configures cgroup resource limits. crun then
   hands off execution to libkrun.

2. **libkrun**: The VMM (Virtual Machine Monitor) that creates and manages the
   microVM. It integrates a minimal set of emulated devices (virtio-blk for
   storage, virtio-fs for file system access, virtio-console for I/O) and
   abstracts away most KVM/hypervisor complexity.

3. **Network stack**: krun supports three networking modes:
   - **TSI (Transparent Socket Impersonation)**: The default mode where libkrun
     intercepts socket operations in the guest and proxies them in the VMM's
     network context. This provides network connectivity without a guest network
     interface. TCP ports listened to by the guest can be published with Podman's
     `-p` flag. Listening on guest SOCK_DGRAM sockets is not supported.
   - **passt**: A user-space networking daemon that provides port forwarding and
     NAT. crun spawns passt with a virtio-net interface backed by a Unix socket
     supplied through `krun_add_net_unixstream()`. crun starts passt with
     `--no-dhcp-dns` and does not provide DNS configuration.
   - **TAP**: Direct attachment to an existing TAP interface via virtio-net, for
     advanced networking scenarios.

When using passt or TAP networking, the microVM has a conventional virtio-net interface, unlike TSI, which provides network connectivity without a guest network interface. With TAP, guest IP addressing and routing must be configured separately.

# NETWORKING

## Networking Modes

### TSI (Transparent Socket Impersonation) - Default

TSI is the default networking mode when no special networking annotations are
used. In this mode:

- libkrun proxies guest socket operations in the VMM's network context
- Network connections originate from the host's IP addresses
- No additional network configuration is needed
- Port publishing works as it would with regular containers
- The guest uses the host's routing table
- Listening on SOCK_DGRAM sockets is not supported

TSI works by intercepting socket system calls in the guest kernel and relaying
them to the host, making the networking appear transparent.

### passt Networking

When the **krun.use_passt** annotation is set, crun spawns the passt daemon to
provide networking:

- crun creates a virtio-net interface backed by a Unix socket supplied through
  `krun_add_net_unixstream()`
- passt binds to privileged ports on the host if allowed (requires CAP_NET_BIND_SERVICE
  or net.ipv4.ip_unprivileged_port_start sysctl)
- passt provides NAT and port forwarding services
- crun starts passt with `--no-dhcp-dns` and does not provide DNS configuration
- The microVM gets its own IP address (typically in a private range)
- Port publishing works via passt's port forwarding configuration

passt is invoked with `-t all -u all` to forward all TCP and UDP ports. Note
that binding to privileged ports (< 1024) requires either the CAP_NET_BIND_SERVICE
capability or setting the net.ipv4.ip_unprivileged_port_start sysctl.

### TAP Networking

When the **krun.tap_name** annotation is set, the microVM attaches to an
existing TAP interface through a virtio-net device:

- Requires libkrun built with virtio-net support
- The TAP interface must already exist in the VMM's network namespace
- The TAP interface must be usable by the user running the VMM
- crun does not create or configure the TAP interface
- `/dev/net/tun` must be available to the VMM
- The guest sees the network device as `eth0`
- Guest IP addressing and routes must be configured separately
- The microVM gets direct layer-2 connectivity to the attached network
- Suitable for advanced networking configurations with bridges, VLANs, etc.
- TSI is disabled when TAP networking is used
- Mutually exclusive with **krun.use_passt**

## Port Publishing

Port publishing behavior depends on the networking mode:

- **TSI mode**: TCP port publishing works like regular containers since libkrun proxies
  socket operations in the VMM's network context. Podman's `-p` flag works for TCP
  ports listened to by the guest. Listening on `SOCK_DGRAM` sockets from the guest
  is not supported.

- **passt mode**: Port publishing works through passt's port forwarding. passt
  forwards all ports by default, but binding to privileged ports requires
  additional system configuration. See passt(1) for details on privileged port
  handling.

- **TAP mode**: Port publishing depends on the TAP interface configuration.
  The host network stack sees traffic from the microVM's MAC address, so port
  publishing must be configured at the network layer (e.g., via iptables rules
  or bridge configuration).

# TROUBLESHOOTING

## Verifying krun Mode

To verify that a container is running in krun mode, check the kernel version
inside the container:

    podman run --runtime krun alpine uname -a

The kernel version will differ from the host kernel, indicating a microVM.

## Network Issues

### TSI Mode

If networking appears broken in TSI mode:
- Verify the host network is functional
- Check that the container has the correct capabilities
- Review crun debug output with `--debug` flag

### passt Mode

If passt networking fails:
- Verify passt is installed at `/usr/bin/passt`
- Check passt logs (currently redirected to /dev/null by crun)
- Verify the passt socket pair was created successfully
- For privileged port issues, check:
  - CAP_NET_BIND_SERVICE capability
  - sysctl net.ipv4.ip_unprivileged_port_start
- Test passt directly with a simple configuration

### TAP Mode

If TAP networking fails:
- Verify the TAP interface exists and is up in the VMM's network namespace:
  `ip link show tap0`
- Check libkrun was built with virtio-net support
- Verify the TAP interface is accessible to the user running the VMM
- Check that `/dev/net/tun` is available to the VMM
- Check for SELinux/AppArmor denials

## Debug Output

Increase crun's verbosity for troubleshooting:

    podman run --runtime krun --log-level=debug ...

This shows detailed information about libkrun initialization, networking setup,
and microVM configuration.

## Checking microVM State

To inspect the microVM's configuration, there are two relevant configuration
files:

1. **OCI config.json**: Kept in the crun state directory (typically
   /run/crun or the configured state root). This contains the OCI container
   configuration.

2. **Guest /.krun_config.json**: Written by crun into the container root
   file system for the guest. This contains the libkrun VM configuration.

For OCI configuration, check the state directory. For VM-specific settings,
inspect the guest-side configuration file from within the container.

## Inspecting Network Layout

To understand the network configuration inside a running krun container:

    podman exec -it <container> ip addr show
    podman exec -it <container> ip route show

This shows the network interfaces and routing table from inside the microVM.
Compare this with the host's network configuration to understand how the
networking mode affects the container's view of the network.

For passt mode, you can also check the passt process on the host:

    ps aux | grep passt

## Common Issues

### Container fails to start with KVM errors

- Verify KVM is available: `lsmod | grep kvm`
- Check hardware virtualization is enabled in BIOS/UEFI
- Verify nested virtualization if using **krun.nested_virt**

### passt fails to start

- Ensure passt is installed at `/usr/bin/passt`
- Check that passt can be executed by the container user
- Verify no firewall rules block passt operation

### Performance issues

- Increase VM memory with krun.ram_mib
- Increase vCPUs with krun.cpus
- Consider using virtio-fs optimization options in a **.krun_vm.json** file

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

The following options are only available through OCI annotations and
are not read from the configuration file: **gpu_flags**,
**use_passt**, **tap_name**, **nested_virt**, and **flavor**.

Example:

    {"cpus": 4, "ram_mib": 2048}

# COMMANDS

See crun.1 man page for the commands available to krun

# SEE ALSO
crun.1
