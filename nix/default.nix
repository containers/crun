{ enableSystemd ? true }:
(import ./nixpkgs.nix {
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation.nix
{
  enableCriu = true;
  enableSystemd = enableSystemd;
}
