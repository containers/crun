let
  static = import ./static.nix;
in
self: super:
{
  criu = (static super.criu);
  gcrypt = (static super.libgcrypt);
  gpgme = (static super.gpgme);
  libassuan = (static super.libassuan);
  libgpgerror = (static super.libgpgerror);
  libseccomp = (static super.libseccomp);
  glib = (static super.glib).overrideAttrs (x: {
    outputs = [ "bin" "out" "dev" ];
    mesonFlags = [
      "-Ddefault_library=static"
      "-Ddevbindir=${placeholder ''dev''}/bin"
      "-Dgtk_doc=false"
      "-Dnls=disabled"
    ];
    postInstall = ''
      moveToOutput "share/glib-2.0" "$dev"
      substituteInPlace "$dev/bin/gdbus-codegen" --replace "$out" "$dev"
      sed -i "$dev/bin/glib-gettextize" -e "s|^gettext_dir=.*|gettext_dir=$dev/share/glib-2.0/gettext|"
      sed '1i#line 1 "${x.pname}-${x.version}/include/glib-2.0/gobject/gobjectnotifyqueue.c"' \
        -i "$dev"/include/glib-2.0/gobject/gobjectnotifyqueue.c
    '';
  });
  libcap = (static super.libcap).overrideAttrs (x: {
    postInstall = ''
      mkdir -p "$doc/share/doc/${x.pname}-${x.version}"
      cp License "$doc/share/doc/${x.pname}-${x.version}/"
      mkdir -p "$pam/lib/security"
      mv "$lib"/lib/security "$pam/lib"
    '';
  });
  systemd = (static super.systemd).overrideAttrs (x: {
    outputs = [ "out" "dev" ];
    mesonFlags = x.mesonFlags ++ [
      "-Dbpf-compiler=gcc"
      "-Dbpf-framework=false"
      "-Dglib=false"
      "-Dstatic-libsystemd=true"
    ];
  });
  yajl = (static super.yajl).overrideAttrs (x: {
    preConfigure = ''
      export CMAKE_STATIC_LINKER_FLAGS="-static"
    '';
  });
  zstd = super.zstd.overrideAttrs (x: {
    cmakeFlags = x.cmakeFlags ++ [ "-DZSTD_BUILD_CONTRIB:BOOL=OFF" ];
    preInstall = "";
  });
}
