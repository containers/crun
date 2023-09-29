{ enableSystemd ? true }:
(import ./nixpkgs.nix {
  crossSystem = {
    config = "aarch64-unknown-linux-gnu";
  };
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation.nix
{
  enableCriu = false;
  enableSystemd = enableSystemd;
}
