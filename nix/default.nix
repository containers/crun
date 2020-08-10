{ system ? builtins.currentSystem, disableSystemd ? false }:
let
  pkgs = (import ./nixpkgs.nix {
    config = {
      packageOverrides = pkg: {
        criu = (static pkg.criu);
        gpgme = (static pkg.gpgme);
        libassuan = (static pkg.libassuan);
        libgpgerror = (static pkg.libgpgerror);
        libseccomp = (static pkg.libseccomp);
        protobufc = (static pkg.protobufc);
        glib = (static pkg.glib).overrideAttrs(x: {
          outputs = [ "bin" "out" "dev" ];
          mesonFlags = [
            "-Ddefault_library=static"
            "-Ddevbindir=${placeholder ''dev''}/bin"
            "-Dgtk_doc=false"
            "-Dnls=disabled"
          ];
        });
        libcap = (static pkg.libcap).overrideAttrs(x: {
          postInstall = ''
            mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
            cp License "$doc/share/doc/${x.pname}-${x.version}/"
            mkdir -p "$pam/lib/security"
            mv "$lib"/lib/security "$pam/lib"
          '';
        });
        systemd = (static pkg.systemd).overrideAttrs(x: {
          mesonFlags = x.mesonFlags ++ [
            "-Dstatic-libsystemd=true"
          ];
          postFixup = ''
            ${x.postFixup}
            sed -ri "s;$out/(.*);$nukedRef/\1;g" $lib/lib/libsystemd.a
          '';
        });
        yajl = (static pkg.yajl).overrideAttrs(x: {
          preConfigure = ''
            export CMAKE_STATIC_LINKER_FLAGS="-static"
          '';
        });
      };
    };
  });

  static = pkg: pkg.overrideAttrs(x: {
    doCheck = false;
    configureFlags = (x.configureFlags or []) ++ [
      "--without-shared"
      "--disable-shared"
    ];
    dontDisableStatic = true;
    enableSharedExecutables = false;
    enableStatic = true;
  });

  self = with pkgs; stdenv.mkDerivation rec {
    name = "crun";
    src = ./..;
    vendorSha256 = null;
    doCheck = false;
    enableParallelBuilding = true;
    outputs = [ "out" ];
    nativeBuildInputs = [ autoreconfHook bash git pkg-config python3 which ];
    buildInputs = [ glibc glibc.static criu libcap libseccomp protobufc systemd yajl ];
    configureFlags = [ "--enable-static" ]
      ++ lib.optional disableSystemd [ "--disable-systemd" ];
    prePatch = ''
      export CFLAGS='-static'
      export LDFLAGS='-s -w -static-libgcc -static'
      export EXTRA_LDFLAGS='-s -w -linkmode external -extldflags "-static -lm"'
      export CRUN_LDFLAGS='-all-static'
      export LIBS='${criu}/lib/libcriu.a ${glibc.static}/lib/libc.a ${glibc.static}/lib/libpthread.a ${glibc.static}/lib/librt.a ${libcap.lib}/lib/libcap.a ${libseccomp.lib}/lib/libseccomp.a ${protobufc}/lib/libprotobuf-c.a ${protobuf}/lib/libprotobuf.a ${systemd.lib}/lib/libsystemd.a ${yajl}/lib/libyajl_s.a'
    '';
    buildPhase = ''
      patchShebangs .
      make
    '';
    installPhase = ''
      install -Dm755 crun $out/bin/crun
    '';
  };
in self
