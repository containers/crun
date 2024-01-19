let
  static = import ./static.nix;
in
self: super:
{
  criu = (static super.criu);
  gpgme = (static super.gpgme);
  libassuan = (static super.libassuan);
  libgpgerror = (static super.libgpgerror);
  libseccomp = (static super.libseccomp);
  libcap = (static super.libcap).overrideAttrs (x: {
    postInstall = ''
      mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
      cp License "$doc/share/doc/${x.pname}-${x.version}/"
      mkdir -p "$pam/lib/security"
      mv "$lib"/lib/security "$pam/lib"
    '';
  });
  libsystemd = (static super.systemdMinimal).overrideAttrs (x: {
    outputs = [ "out" "dev" ];
    mesonFlags = x.mesonFlags ++ [
      "-Dbpf-compiler=gcc"
      "-Dbpf-framework=false"
      "-Dglib=false"
      "-Dstatic-libsystemd=true"
    ];
  });
  yajl = super.yajl.overrideAttrs (x: {
    cmakeFlags = (x.cmakeFlags or [ ]) ++ [
      "-DBUILD_SHARED_LIBS=OFF"
    ];
  });
  zstd = super.zstd.overrideAttrs (x: {
    cmakeFlags = x.cmakeFlags ++ [ "-DZSTD_BUILD_CONTRIB:BOOL=OFF" ];
    preInstall = "";
  });
}
