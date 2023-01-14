{ system ? builtins.currentSystem, enableSystemd ? true }:
let
  static = import ./static.nix;
  pkgs = (import ./nixpkgs.nix {
    config = {
      packageOverrides = pkg: {
        gcrypt = (static pkg.libgcrypt);
        criu = (static pkg.criu);
        gpgme = (static pkg.gpgme);
        libassuan = (static pkg.libassuan);
        libgpgerror = (static pkg.libgpgerror);
        libseccomp = (static pkg.libseccomp);
        glib = (static pkg.glib).overrideAttrs (x: {
          outputs = [ "bin" "out" "dev" ];
          mesonFlags = [
            "-Ddefault_library=static"
            "-Ddevbindir=${placeholder ''dev''}/bin"
            "-Dgtk_doc=false"
            "-Dnls=disabled"
          ];
        });
        libcap = (static pkg.libcap).overrideAttrs (x: {
          postInstall = ''
            mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
            cp License "$doc/share/doc/${x.pname}-${x.version}/"
            mkdir -p "$pam/lib/security"
            mv "$lib"/lib/security "$pam/lib"
          '';
        });
        systemd = (static pkg.systemd).overrideAttrs (x: {
          outputs = [ "out" "dev" ];
          mesonFlags = x.mesonFlags ++ [
            "-Dglib=false"
            "-Dstatic-libsystemd=true"
          ];
        });
        yajl = (static pkg.yajl).overrideAttrs (x: {
          preConfigure = ''
            export CMAKE_STATIC_LINKER_FLAGS="-static"
          '';
        });
      };
    };
  });

  self = with pkgs; stdenv.mkDerivation rec {
    name = "crun";
    src = ./..;
    vendorSha256 = null;
    doCheck = false;
    enableParallelBuilding = true;
    outputs = [ "out" ];
    nativeBuildInputs = [
      autoreconfHook
      bash
      gitMinimal
      pkg-config
      python3
      which
    ];
    buildInputs = [
      gcrypt
      criu
      glibc
      glibc.static
      libcap
      libseccomp
      systemd
      yajl
    ];
    configureFlags = [ "--enable-static" ]
      ++ lib.optional (!enableSystemd) [ "--disable-systemd" ];
    prePatch = ''
      export CFLAGS='-static -pthread'
      export LDFLAGS='-s -w -static-libgcc -static'
      export EXTRA_LDFLAGS='-s -w -linkmode external -extldflags "-static -lm"'
      export CRUN_LDFLAGS='-all-static'
      export LIBS='${criu}/lib/libcriu.a ${glibc.static}/lib/libc.a ${glibc.static}/lib/libpthread.a ${glibc.static}/lib/librt.a ${lib.getLib libcap}/lib/libcap.a ${lib.getLib libseccomp}/lib/libseccomp.a ${lib.getLib systemd}/lib/libsystemd.a ${yajl}/lib/libyajl_s.a ${gcrypt}/lib/libgcrypt.a'
    '';
    buildPhase = ''
      patchShebangs .
      make
    '';
    installPhase = ''
      install -Dm755 crun $out/bin/crun
    '';
  };
in
self
