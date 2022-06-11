{ lib
, python3Packages
, wrapQtAppsHook
, writeText
, makeDesktopItem
}:

python3Packages.buildPythonApplication rec {
  pname = "streamdeck-ui";
  version = "2.0.4";

  src = python3Packages.fetchPypi {
    pname = "streamdeck_ui";
    inherit version;
    sha256 = "650bef0da4957e0d2e2b4cd9c74a55715bcf1526d9ef2cdd04271364117a5845";
  };

  # Add udev rules to allow non-root access to the Stream Deck.
  # To enable these rules on NixOS, add this to your system configuration:
  #
  #     services.udev.packages = [ pkgs.streamdeck-ui ];
  postInstall =
    let
      udevRulesName = "70-streamdeck.rules";
      udevRules = ''
        SUBSYSTEM=="usb", ATTRS{idVendor}=="0fd9", ATTRS{idProduct}=="0060", TAG+="uaccess"
        SUBSYSTEM=="usb", ATTRS{idVendor}=="0fd9", ATTRS{idProduct}=="0063", TAG+="uaccess"
        SUBSYSTEM=="usb", ATTRS{idVendor}=="0fd9", ATTRS{idProduct}=="006c", TAG+="uaccess"
        SUBSYSTEM=="usb", ATTRS{idVendor}=="0fd9", ATTRS{idProduct}=="006d", TAG+="uaccess"
        SUBSYSTEM=="usb", ATTRS{idVendor}=="0fd9", ATTRS{idProduct}=="0080", TAG+="uaccess"
      '';
      desktopItem =
        (makeDesktopItem {
          name = "Stream Deck UI";
          desktopName = "Stream Deck UI";
          icon = "streamdeck-ui";
          exec = "streamdeck";
          comment = "UI for the Elgato Stream Deck";
          categories = [ "Utility" ];
        });
    in
      ''
        mkdir -p "$out/etc/udev/rules.d"
        cp ${writeText udevRulesName udevRules} $out/etc/udev/rules.d/${udevRulesName}

        mkdir -p "$out/share/applications" "$out/share/pixmaps"
        cp ${desktopItem}/share/applications/* $out/share/applications
        cp streamdeck_ui/logo.png $out/share/pixmaps/streamdeck-ui.png
      '';

  dontWrapQtApps = true;
  makeWrapperArgs = [ "\${qtWrapperArgs[@]}" ];

  nativeBuildInputs = [ wrapQtAppsHook ];

  propagatedBuildInputs = with python3Packages; [
    setuptools
    filetype
    cairosvg
    pillow
    pynput
    pyside2
    streamdeck
    xlib
  ];

  # Skip tests because they require an X server
  doCheck = false;

  meta = with lib; {
    description = "A Linux compatible UI for the Elgato Stream Deck";
    homepage = "https://timothycrosley.github.io/streamdeck-ui/";
    license = licenses.mit;
    maintainers = with maintainers; [ majiir ];
  };
}

