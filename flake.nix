{
  description = "crun - a fast and low-memory footprint OCI Container Runtime";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      archConfigs = {
        amd64 = {
          system = "x86_64-linux";
          crossSystem = null;
          enableCriu = true;
        };
        arm64 = {
          system = "x86_64-linux";
          crossSystem.config = "aarch64-unknown-linux-gnu";
          enableCriu = false;
        };
        ppc64le = {
          system = "x86_64-linux";
          crossSystem.config = "powerpc64le-unknown-linux-gnu";
          enableCriu = false;
        };
        riscv64 = {
          system = "x86_64-linux";
          crossSystem.config = "riscv64-unknown-linux-gnu";
          enableCriu = false;
        };
        s390x = {
          system = "x86_64-linux";
          crossSystem.config = "s390x-unknown-linux-musl";
          enableCriu = false;
        };
      };

      mkCrunPackage = arch: { system, crossSystem, enableCriu }: enableSystemd:
        let
          # https://github.com/madler/zlib/issues/1200
          # Only patch target-platform zlib so native build tools stay cached.
          zlibOverlay = final: prev: {
            zlib = if final.stdenv.hostPlatform.isS390x
              then prev.zlib.overrideAttrs (old: {
                postPatch = (old.postPatch or "") + ''
                  substituteInPlace configure --replace-fail \
                    '/^ZINCOUT *=/s#=.*#=$ZINCOUT#' \
                    '/^ZINCOUT *=/s#=.*#=$ZINCOUT#
/^VGFMAFLAG *=/s#=.*#=$VGFMAFLAG#'
                  substituteInPlace contrib/crc32vx/crc32_vx.c --replace-fail \
                    'HWCAP_S390_VX' 'HWCAP_S390_VXRS'
                '';
              })
              else prev.zlib;
          };
          needsZlibFix = crossSystem != null
            && crossSystem ? config
            && builtins.match ".*s390x.*" crossSystem.config != null;
          overlays = if needsZlibFix then [ zlibOverlay ] else [];
          pkgsArgs = { inherit system overlays; }
            // (if crossSystem != null then { inherit crossSystem; } else {});
          pkgs = import nixpkgs pkgsArgs;
          static = import ./nix/static.nix;

          # Build static variants locally — these don't pollute the global package set
          staticLibcap = (static pkgs.libcap).overrideAttrs (x: {
            postInstall = ''
              mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
              cp License "$doc/share/doc/${x.pname}-${x.version}/"
              mkdir -p "$pam/lib/security"
              mv "$lib"/lib/security "$pam/lib"
            '';
          });
          staticLibseccomp = static pkgs.libseccomp;
          staticYajl = pkgs.yajl.overrideAttrs (x: {
            cmakeFlags = (x.cmakeFlags or []) ++ [ "-DBUILD_SHARED_LIBS=OFF" ];
          });
          staticSystemd = (static pkgs.systemdMinimal).overrideAttrs (x: {
            outputs = [ "out" "dev" ];
            mesonFlags = x.mesonFlags ++ [
              "-Dbpf-compiler=gcc"
              "-Dbpf-framework=false"
              "-Dglib=false"
              "-Dstatic-libsystemd=true"
            ];
            # TODO: remove when https://github.com/systemd/systemd/issues/30448
            # got resolved or fixed in nixpkgs.
            preConfigure = ''
              export NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -Wno-error=format-overflow"
            '';
          });
          staticCriu = let
            staticProtobufc = pkgs.protobufc.overrideAttrs (x: {
              configureFlags = (x.configureFlags or []) ++ [ "--enable-static" ];
            });
            staticLibnl = pkgs.libnl.overrideAttrs (x: {
              configureFlags = (x.configureFlags or []) ++ [ "--enable-static" ];
            });
            staticLibnet = pkgs.libnet.overrideAttrs (x: {
              configureFlags = (x.configureFlags or []) ++ [ "--enable-static" ];
            });
          in (static pkgs.criu).overrideAttrs (x: {
            buildInputs = (x.buildInputs or []) ++ [
              pkgs.protobuf
              staticProtobufc
              staticLibnl
              staticLibnet
            ];
            NIX_LDFLAGS = "${x.NIX_LDFLAGS or ""} -lprotobuf-c";
            buildPhase = ''
              make lib
            '';
          });
        in
          pkgs.callPackage ./nix/derivation.nix {
            inherit enableCriu enableSystemd;
            libcap = staticLibcap;
            libseccomp = staticLibseccomp;
            yajl = staticYajl;
            libsystemd = staticSystemd;
            criu = staticCriu;
          };

      # Generate packages for all architectures and variants
      packages = builtins.foldl' (acc: arch:
        let cfg = archConfigs.${arch}; in
        acc // {
          "crun-static-${arch}" = mkCrunPackage arch cfg true;
          "crun-static-${arch}-disable-systemd" = mkCrunPackage arch cfg false;
        }
      ) {} (builtins.attrNames archConfigs);

    in {
      packages.x86_64-linux = packages;
    };
}
