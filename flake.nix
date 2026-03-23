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
          pkgsArgs = {
            inherit system;
            overlays = [ (import ./nix/overlay.nix) ];
          } // (if crossSystem != null then { inherit crossSystem; } else {});
          pkgs = import nixpkgs pkgsArgs;
        in
          pkgs.callPackage ./nix/derivation.nix {
            inherit enableCriu enableSystemd;
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
