{ pkgs
, enableCriu
, enableSystemd
}:
with pkgs; stdenv.mkDerivation {
  name = "crun";
  src = ./..;
  vendorSha256 = null;
  doCheck = false;
  enableParallelBuilding = true;
  outputs = [ "out" ];
  nativeBuildInputs = with buildPackages; [
    autoreconfHook
    bash
    gitMinimal
    pkg-config
    python3
    which
  ];
  buildInputs = [
    gcrypt
    glibc
    glibc.static
    libcap
    libseccomp
    libsystemd
    yajl
  ] ++ lib.optionals enableCriu [ criu ];
  configureFlags = [ "--enable-static" ] ++ lib.optional (!enableSystemd) [ "--disable-systemd" ];
  prePatch = ''
    export CFLAGS='-static -pthread'
    export LDFLAGS='-s -w -static-libgcc -static'
    export EXTRA_LDFLAGS='-s -w -linkmode external -extldflags "-static -lm"'
    export CRUN_LDFLAGS='-all-static'
    export LIBS='${lib.optionalString enableCriu "${criu}/lib/libcriu.a"} ${glibc.static}/lib/libc.a ${glibc.static}/lib/libpthread.a ${glibc.static}/lib/librt.a ${lib.getLib libcap}/lib/libcap.a ${lib.getLib libseccomp}/lib/libseccomp.a ${lib.optionalString enableSystemd "${lib.getLib libsystemd}/lib/libsystemd.a"} ${yajl}/lib/libyajl.a ${gcrypt}/lib/libgcrypt.a'
  '';
  buildPhase = ''
    patchShebangs .
    make
  '';
  installPhase = ''
    install -Dm755 crun $out/bin/crun
  '';
}
