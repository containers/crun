{ stdenv
, pkgs
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
    autoPatchelfHook
    bash
    gitMinimal
    pkg-config
    python3
    which
  ];
  buildInputs =
    (if stdenv.hostPlatform.isMusl then [
      argp-standalone
    ] else [
      glibc
      glibc.static
    ]) ++ [
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
    export LIBS='${lib.optionalString enableCriu "${criu}/lib/libcriu.a"} ${if stdenv.hostPlatform.isMusl then "${musl}/lib/libc.a ${musl}/lib/libpthread.a ${musl}/lib/librt.a" else "${glibc.static}/lib/libc.a ${glibc.static}/lib/libpthread.a ${glibc.static}/lib/librt.a"} ${lib.getLib libcap}/lib/libcap.a ${lib.getLib libseccomp}/lib/libseccomp.a ${lib.optionalString enableSystemd "${lib.getLib libsystemd}/lib/libsystemd.a"} ${yajl}/lib/libyajl.a'
  '';
  buildPhase = ''
    patchShebangs .
    make -C libocispec libocispec.la
    make git-version.h crun
  '';
  installPhase = ''
    install -Dm755 crun $out/bin/crun
  '';
}
