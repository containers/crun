{ system ? builtins.currentSystem }:
let
  pkgs = (import ./nixpkgs.nix {
    config = {
      packageOverrides = pkg: {
        libcap = (static pkg.libcap).overrideAttrs(x: {
          postInstall = ''
            mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
            cp License "$doc/share/doc/${x.pname}-${x.version}/"
            mkdir -p "$pam/lib/security"
            mv "$lib"/lib/security "$pam/lib"
          '';
        });
        libseccomp = (static pkg.libseccomp);
        protobufc = (static pkg.protobufc);
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
    configureFlags = (x.configureFlags or []) ++ [ "--disable-shared" ];
    enableStatic = true;
  });

  self = with pkgs; {
    crun-static = (crun.overrideAttrs(x: {
      name = "crun-static";
      src = ./..;
      doCheck = false;
      nativeBuildInputs = [ autoreconfHook pkgconfig python3 ];
      buildInputs = x.buildInputs ++ [ criu glibc glibc.static ];
      configureFlags = [ "--enable-static-nss" ];
      prePatch = ''
        export LDFLAGS="-static-libgcc -static"
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
        echo "Using static libs: $LIBS"
      '';
    })).override {
      yajl = yajl.overrideAttrs(x: {
        buildInputs = [ glibc glibc.static ];
        preConfigure = ''
          export CMAKE_STATIC_LINKER_FLAGS="-static"
        '';
      });
    };
  };
in self
