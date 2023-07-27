%global krun_opts %{nil}
%global wasmedge_opts %{nil}
%global wasmtime_opts %{nil}

# krun and wasm[edge,time] support only on aarch64 and x86_64
%ifarch aarch64 || x86_64
%global wasm_support 1

# wasmedge only found on Fedora and environments with epel enabled
%if %{defined fedora} || (%{defined copr_project} && "%{copr_project}" == "podman-next")
%global wasmedge_support 1
%global wasmedge_opts --with-wasmedge
%endif

# krun only exists on fedora
%if %{defined fedora}
%global krun_support 1
%global krun_opts --with-libkrun
%endif

# wasmtime exists only on podman-next copr for now
%if %{defined copr_project} && "%{?copr_project}" == "podman-next"
%global wasmtime_support 1
%global wasmtime_opts --with-wasmtime
%endif

%endif

Summary: OCI runtime written in C
Name: crun
%if %{defined copr_username}
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
Source0: %{url}/releases/download/%{version}/%{name}-%{version}.tar.xz
License: GPL-2.0-only
URL: https://github.com/containers/%{name}
%if %{defined golang_arches_future}
ExclusiveArch: %{golang_arches_future}
%else
ExclusiveArch: aarch64 ppc64le s390x x86_64
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
BuildRequires: %{_bindir}/go-md2man
%if %{defined wasmedge_support}
BuildRequires: wasmedge-devel
%endif
%if %{defined wasmtime_support}
BuildRequires: wasmtime-c-api-devel
%endif
%if %{defined rhel} && 0%{?rhel} == 8
BuildRequires: python3
%else
BuildRequires: python
%endif
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
Requires: wasm-library
Recommends: wasmedge

%description wasm
%{name}-wasm is a symlink to the %{name} binary, with wasm as an additional dependency.
%endif

%prep
%autosetup -Sgit -n %{name}-%{version}

%build
./autogen.sh
./configure --disable-silent-rules %{krun_opts} %{wasmedge_opts} %{wasmtime_opts}
%make_build

%install
%make_install prefix=%{_prefix}
rm -rf %{buildroot}%{_prefix}/lib*

%if %{defined krun_support}
ln -s %{_bindir}/%{name} %{buildroot}%{_bindir}/krun
%endif

%if %{defined wasm_support}
ln -s %{_bindir}/%{name} %{buildroot}%{_bindir}/%{name}-wasm
%endif

%files
%license COPYING
%{_bindir}/%{name}
%{_mandir}/man1/*

%if %{defined krun_support}
%files krun
%license COPYING
%{_bindir}/krun
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
