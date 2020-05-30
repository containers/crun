{ system ? builtins.currentSystem }:
let
  pkgs = (import ./nixpkgs.nix {
    config = {
      packageOverrides = pkg: {
        libseccomp = (static pkg.libseccomp);
        protobufc = (static pkg.protobufc);
        libcap = (static pkg.libcap).overrideAttrs(x: {
          postInstall = ''
            mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
            cp License "$doc/share/doc/${x.pname}-${x.version}/"
            mkdir -p "$pam/lib/security"
            mv "$lib"/lib/security "$pam/lib"
          '';
        });
        yajl = (static pkg.yajl).overrideAttrs(x: {
          preConfigure = ''
            export CMAKE_STATIC_LINKER_FLAGS="-static"
          '';
        });
        systemd = pkg.systemd.overrideAttrs(x: {
          mesonFlags = x.mesonFlags ++ [ "-Dstatic-libsystemd=true" ];
          postFixup = ''
            ${x.postFixup}
            sed -ri "s;$out/(.*);$nukedRef/\1;g" $lib/lib/libsystemd.a
          '';
        });
      };
    };
  });

  static = pkg: pkg.overrideAttrs(x: {
    configureFlags = (x.configureFlags or []) ++
      [ "--without-shared" "--disable-shared" ];
    dontDisableStatic = true;
    enableSharedExecutables = false;
    enableStatic = true;
  });

  self = with pkgs; stdenv.mkDerivation rec {
    name = "crun";
    src = ./..;
    doCheck = false;
    enableParallelBuilding = true;
    nativeBuildInputs = [ autoreconfHook go-md2man pkg-config python3 ];
    buildInputs = [ criu glibc glibc.static libcap libseccomp systemd yajl ];
    configureFlags = [ "--enable-static-nss" ];
    prePatch = ''
      export LDFLAGS="-static-libgcc -static -s -w"
      export CRUN_LDFLAGS="-all-static"
      export LIBS="\
        ${criu}/lib/libcriu.a \
        ${glibc.static}/lib/libc.a \
        ${glibc.static}/lib/libpthread.a \
        ${glibc.static}/lib/librt.a \
        ${libcap.lib}/lib/libcap.a \
        ${libseccomp.lib}/lib/libseccomp.a \
        ${protobufc}/lib/libprotobuf-c.a \
        ${protobuf}/lib/libprotobuf.a \
        ${systemd.lib}/lib/libsystemd.a \
        ${yajl}/lib/libyajl_s.a \
      "
    '';
    postPatch = ''
      cat Makefile | egrep '^VERSION = ' | sed 's/^VERSION = //g' > .tarball-version
      echo "#define GIT_VERSION \"$(cat .tarball-version)\"" > git-version.h
    '';
  };
in self
