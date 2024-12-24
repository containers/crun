{ enableSystemd ? true }:
(import ./nixpkgs.nix {
  overlays = [ (import ./overlay.nix) ];
}).callPackage ./derivation.nix
{
  enableCriu = true;
  enableSystemd = enableSystemd;
}
{ pkgs ? import <nixpkgs> {} }: pkgs.mkShell { 
    packages = with pkgs; [ jansson ]; 
}

