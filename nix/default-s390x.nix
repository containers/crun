{ enableSystemd ? true }:
(import ./nixpkgs.nix {
  crossSystem = {
    config = "s390x-unknown-linux-musl";
  };
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation.nix
{
  enableCriu = false;
  enableSystemd = enableSystemd;
}
