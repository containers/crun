%global krun_opts %{nil}
%global wasmedge_opts %{nil}

# krun and wasm[edge,time] support only on aarch64 and x86_64
%ifarch aarch64 || x86_64

%if %{defined copr_username}
%define copr_build 1
%endif

# Disable wasmedge on rhel 10 until EPEL10 is in place, otherwise it causes
# build issues on copr
%if %{defined fedora} || (%{defined %copr_build} && %{defined rhel} && 0%{?rhel} < 10)
%global wasmedge_support 1
%global wasmedge_opts --with-wasmedge
%global wasm_support 1
%endif

# krun only exists on fedora
%if %{defined fedora}
%global krun_support 1
%global krun_opts --with-libkrun
%endif

%endif

Summary: OCI runtime written in C
Name: crun
%if %{defined copr_build}
Epoch: 102
%endif
# DO NOT TOUCH the Version string!
# The TRUE source of this specfile is:
# https://github.com/containers/crun/blob/main/rpm/crun.spec
# If that's what you're reading, Version must be 0, and will be updated by Packit for
# copr and koji builds.
# If you're reading this on dist-git, the version is automatically filled in by Packit.
Version: 0
Release: %autorelease
URL: https://github.com/containers/%{name}
Source0: %{url}/releases/download/%{version}/%{name}-%{version}.tar.zst
License: GPL-2.0-only
%if %{defined golang_arches_future}
ExclusiveArch: %{golang_arches_future}
%else
ExclusiveArch: aarch64 ppc64le riscv64 s390x x86_64
%endif
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: gcc
BuildRequires: git-core
BuildRequires: gperf
BuildRequires: libcap-devel
%if %{defined krun_support}
BuildRequires: libkrun-devel
%endif
BuildRequires: systemd-devel
BuildRequires: yajl-devel
BuildRequires: libseccomp-devel
BuildRequires: python3-libmount
BuildRequires: libtool
BuildRequires: protobuf-c-devel
BuildRequires: criu-devel >= 3.17.1-2
Recommends: criu >= 3.17.1
Recommends: criu-libs
%if %{defined wasmedge_support}
BuildRequires: wasmedge-devel
%endif
BuildRequires: python
Provides: oci-runtime

%description
%{name} is a OCI runtime

%if %{defined krun_support}
%package krun
Summary: %{name} with libkrun support
Requires: libkrun
Requires: %{name} = %{?epoch:%{epoch}:}%{version}-%{release}
Provides: krun = %{?epoch:%{epoch}:}%{version}-%{release}

%description krun
krun is a symlink to the %{name} binary, with libkrun as an additional dependency.
%endif

%if %{defined wasm_support}
%package wasm
Summary: %{name} with wasm support
Requires: %{name} = %{?epoch:%{epoch}:}%{version}-%{release}
# The hard dep on wasm-library is causing trouble in internal testing farm
# with RHEL.
%if %{defined fedora}
Requires: wasm-library
%else
Recommends: wasm-library
%endif
Recommends: wasmedge

%description wasm
%{name}-wasm is a symlink to the %{name} binary, with wasm as an additional dependency.
%endif

%prep
%autosetup -Sgit -n %{name}-%{version}

%build
./autogen.sh
./configure --disable-silent-rules %{krun_opts} %{wasmedge_opts}
%make_build

%install
%make_install prefix=%{_prefix}
rm -rf %{buildroot}%{_prefix}/lib*

%files
%license COPYING
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1.gz

%if %{defined krun_support}
%files krun
%license COPYING
%{_bindir}/krun
%{_mandir}/man1/krun.1.gz
%endif

%if %{defined wasm_support}
%files wasm
%license COPYING
%{_bindir}/%{name}-wasm
%endif

%changelog
%if %{defined autochangelog}
%autochangelog
%else
# NOTE: This changelog will be visible on CentOS 8 Stream builds
# Other envs are capable of handling autochangelog
* Tue Jun 13 2023 RH Container Bot <rhcontainerbot@fedoraproject.org>
- Placeholder changelog for envs that are not autochangelog-ready.
- Contact upstream if you need to report an issue with the build.
%endif
