{ lib
, stdenv
, fetchurl
, unzip
, wine
, unshield
, makeWrapper
, oraclejre8
, callPackage
}:

# To acquire oraclejre8:
#
# wget https://javadl.oracle.com/webapps/download/AutoDL?BundleId=244045_89d678f2be164786b292527658ca1605
# (link at https://gist.github.com/wavezhang/ba8425f24a968ec9b2a8619d7c2d86a6?permalink_comment_id=3601058#gistcomment-3601058)
# Compare sha256sum with https://www.oracle.com/webfolder/s/digest/8u281checksum.html
# nix-store --add-fixed sha256 jdk-8u281-linux-x64.tar.gz

stdenv.mkDerivation rec {
  pname = "tplink-escu";
  version = "1.3.10";
  fullVersion = "${version}.0";

  src = fetchurl {
    url = "https://static.tp-link.com/upload/software/2022/202204/20220412/Easy%20Smart%20Configuration%20Utility%20v${fullVersion}.zip";
    hash = "sha256-9T3Ln1vRBZRr+ImQfZxgTXKmjr1ECfZdeRaxkOJfF+g=";
  };

  nativeBuildInputs = [
    unzip
    wine
    unshield
    makeWrapper
  ];

  unpackPhase = ''
    runHook preUnpack

    unzip $src

    mkdir extract .wine
    WINEPREFIX=$(readlink -f .wine) wine "Easy Smart Configuration Utility v${fullVersion}.exe" /extract_all:extract

    unshield x extract/Disk1/data1.cab "Easy Smart Configuration Utility.exe"

    mkdir -p $out/share/tplink-escu
    cp 'DefaultComponent/Easy Smart Configuration Utility.exe' $out/share/tplink-escu/easysmart.jar

    runHook postUnpack
  '';

  # TODO: Get the .desktop file! and icon

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    makeWrapper ${oraclejre8}/bin/java $out/bin/tplink-escu \
      --add-flags "-jar $out/share/tplink-escu/easysmart.jar"

    runHook postInstall
  '';

  # TODO: Wrapper that handles forwarding the incoming broadcasts to the right interface

  meta = with lib; {
    description = "Configuration utility for TP-Link Easy Smart devices";
    homepage = "https://www.tp-link.com/en/support/download/tl-sg105e/#Easy_Smart_Configuration_Utility";
    license = licenses.unfree;
    maintainers = with maintainers; [ majiir ];
    platforms = [ "x86_64-linux" ]; # TODO: Check for ARM! Maybe this runs on all unix.
  };
}
