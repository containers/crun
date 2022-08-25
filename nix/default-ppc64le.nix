{ enableSystemd ? true }:
let
  static = import ./static.nix;
  pkgs = (import ./nixpkgs.nix {
    crossSystem = {
      config = "powerpc64le-unknown-linux-gnu";
    };
    config = {
      packageOverrides = pkg: {
        gpgme = (static pkg.gpgme);
        libassuan = (static pkg.libassuan);
        libgpgerror = (static pkg.libgpgerror);
        libseccomp = (static pkg.libseccomp);
        protobufc = (static pkg.protobufc);
        glib = (static pkg.glib).overrideAttrs (x: {
          outputs = [ "bin" "out" "dev" ];
          mesonFlags = [
            "-Ddefault_library=static"
            "-Ddevbindir=${placeholder ''dev''}/bin"
            "-Dgtk_doc=false"
            "-Dnls=disabled"
          ];
          postInstall = ''
            moveToOutput "share/glib-2.0" "$dev"
            substituteInPlace "$dev/bin/gdbus-codegen" --replace "$out" "$dev"
            sed -i "$dev/bin/glib-gettextize" -e "s|^gettext_dir=.*|gettext_dir=$dev/share/glib-2.0/gettext|"
            sed '1i#line 1 "${x.pname}-${x.version}/include/glib-2.0/gobject/gobjectnotifyqueue.c"' \
              -i "$dev"/include/glib-2.0/gobject/gobjectnotifyqueue.c
          '';
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
            "-Dbpf-compiler=gcc"
            "-Dbpf-framework=false"
            "-Dstatic-libsystemd=true"
          ];
        });
        yajl = (static pkg.yajl).overrideAttrs (x: {
          preConfigure = ''
            export CMAKE_STATIC_LINKER_FLAGS="-static"
          '';
        });
        zstd = pkg.zstd.overrideAttrs (x: {
          cmakeFlags = x.cmakeFlags ++ [ "-DZSTD_BUILD_CONTRIB:BOOL=OFF" ];
          preInstall = "";
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
    nativeBuildInputs = with buildPackages; [
      autoreconfHook
      bash
      gitMinimal
      pkg-config
      python3
      which
    ];
    buildInputs = [
      glibc
      glibc.static
      libcap
      libseccomp
      protobufc
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
      export LIBS='${glibc.static}/lib/libc.a ${glibc.static}/lib/libpthread.a ${glibc.static}/lib/librt.a ${lib.getLib libcap}/lib/libcap.a ${lib.getLib libseccomp}/lib/libseccomp.a ${protobufc}/lib/libprotobuf-c.a ${lib.getLib systemd}/lib/libsystemd.a ${yajl}/lib/libyajl_s.a'
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
