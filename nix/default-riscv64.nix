{ enableSystemd ? true }:
(import ./nixpkgs.nix {
  crossSystem = {
    config = "riscv64-unknown-linux-gnu";
  };
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation.nix
{
  enableCriu = false;
  enableSystemd = enableSystemd;
}
