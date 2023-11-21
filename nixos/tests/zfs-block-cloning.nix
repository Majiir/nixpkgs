{ system ? builtins.currentSystem,
  config ? {},
  pkgs ? import ../.. { inherit system config; }
}:

with import ../lib/testing-python.nix { inherit system pkgs; };

let

  makeZfsTest = name:
    { kernelPackage ? if enableUnstable
                      then pkgs.zfsUnstable.latestCompatibleLinuxPackages
                      else pkgs.linuxPackages
    , enableUnstable ? false
    , enableSystemdStage1 ? false
    }:
    makeTest {
      name = "zfs-" + name;
      meta = with pkgs.lib.maintainers; {
        maintainers = [ majiir ];
      };

      nodes.machine = { pkgs, lib, ... }: {
        virtualisation = {
          emptyDiskImages = [ 4096 ];
          useBootLoader = true;
          useEFIBoot = true;
        };
        boot.loader.systemd-boot.enable = true;
        boot.loader.timeout = 0;
        boot.loader.efi.canTouchEfiVariables = true;
        networking.hostId = "deadbeef";
        boot.kernelPackages = kernelPackage;
        boot.supportedFilesystems = [ "zfs" ];
        boot.zfs.enableUnstable = enableUnstable;
        boot.initrd.systemd.enable = enableSystemdStage1;

        environment.systemPackages = [ pkgs.parted ];

        # /dev/disk/by-id doesn't get populated in the NixOS test framework
        boot.zfs.devNodes = "/dev/disk/by-uuid";
      };

      testScript = ''
        machine.wait_for_unit("multi-user.target")
        machine.succeed(
            "zpool status",
            "parted --script /dev/vdb mklabel msdos",
            "parted --script /dev/vdb -- mkpart primary 1024M -1s",
            "zpool create rpool /dev/vdb1 -m /mnt",
            "echo passphrase | zfs create rpool/encrypted -o encryption=on -o keyformat=passphrase",
            "zfs create rpool/encrypted/ds1",
            "dd if=/dev/urandom of=/mnt/encrypted/ds1/testfile bs=1M count=128",
            "zfs snapshot rpool/encrypted/ds1@s1",
            "zfs send -w rpool/encrypted/ds1@s1 | zfs recv rpool/encrypted/ds2",
            "echo passphrase | zfs load-key rpool/encrypted/ds2",
            "zfs mount rpool/encrypted/ds2",
            "cp /mnt/encrypted/ds1/testfile /mnt/encrypted/ds2/anotherfile",
        )

        machine.shutdown()
        machine.start()

        machine.wait_for_unit("multi-user.target")
        machine.succeed(
            "zpool import rpool",
            "echo passphrase | zfs load-key rpool/encrypted",
            "echo passphrase | zfs load-key rpool/encrypted/ds2",
            "zfs mount -a",
            "echo newpassphrase | zfs change-key -o keyformat=passphrase rpool/encrypted/ds2",
            "sync",
            "cp /mnt/encrypted/ds1/testfile /mnt/encrypted/ds2/yetanotherfile",
            "sync",
        )
      '';
    };

in {

  stable = makeZfsTest "stable" { };

  unstable = makeZfsTest "unstable" {
    enableUnstable = true;
  };

  unstableWithSystemdStage1 = makeZfsTest "unstable" {
    enableUnstable = true;
    enableSystemdStage1 = true;
  };

}
