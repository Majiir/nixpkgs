import ./make-test-python.nix ({ lib, pkgs, ...}: {
  name = "dot-mount-reproducer";

  meta = with lib.maintainers; {
    maintainers = [ majiir ];
  };

  nodes = {
    machine = { ... }: {
      virtualisation = {
        emptyDiskImages = [ 1024 ];
        useBootLoader = true;
        useEFIBoot = true;
      };
      boot.loader.systemd-boot.enable = true;
      boot.loader.timeout = 0;
      boot.loader.efi.canTouchEfiVariables = true;
      boot.initrd.systemd.enable = true;

      specialisation.mount.configuration = {
        virtualisation.fileSystems = {
          "/.foo" = {
            device = "/dev/disk/by-label/data";
            fsType = "ext4";
            neededForBoot = true;
          };
        };
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed(
        "${pkgs.e2fsprogs}/bin/mkfs.ext4 -L data /dev/vdb",
        "bootctl set-default nixos-generation-1-specialisation-mount.conf",
        "sync"
    )
    machine.crash()

    machine.wait_for_unit("multi-user.target")

    machine.succeed("touch /.foo/bar")
    machine.succeed("stat /.foo/bar")

    # We never configured /foo (without a dot), so this should fail.
    machine.fail("stat /foo/bar")
  '';
})
