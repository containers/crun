let
  static = import ./static.nix;
in
self: super:
{
  protobufc = super.protobufc.overrideAttrs (x: {
    configureFlags = (x.configureFlags or [ ]) ++ [ "--enable-static" ];
  });
  libnl = super.libnl.overrideAttrs (x: {
    configureFlags = (x.configureFlags or [ ]) ++ [ "--enable-static" ];
  });
  libnet = super.libnet.overrideAttrs (x: {
    configureFlags = (x.configureFlags or [ ]) ++ [ "--enable-static" ];
  });
  criu = (static super.criu).overrideAttrs (x: {
    buildInputs = (x.buildInputs or []) ++ [
      super.protobuf
      super.protobufc
      super.libnl
      super.libnet
    ];
    NIX_LDFLAGS = "${x.NIX_LDFLAGS or ""} -lprotobuf-c";
    buildPhase = ''
      make lib
    '';
  });
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
    # TODO: remove when https://github.com/systemd/systemd/issues/30448
    # got resolved or fixed in nixpkgs.
    preConfigure = ''
      export NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -Wno-error=format-overflow"
    '';
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
