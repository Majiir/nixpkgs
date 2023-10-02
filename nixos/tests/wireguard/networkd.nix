import ../make-test-python.nix ({ pkgs, lib, kernelPackages ? null, ...} :
  let
    wg-snakeoil-keys = import ./snakeoil-keys.nix;
    peer = (import ./make-peer.nix) { inherit lib; };
  in
  {
    name = "wireguard";
    meta = with pkgs.lib.maintainers; {
      maintainers = [ majiir ];
    };

    nodes = {
      peer0 = peer {
        ip4 = "192.168.0.1";
        ip6 = "fd00::1";
        extraConfig = {
          boot = lib.mkIf (kernelPackages != null) { inherit kernelPackages; };
          networking.useNetworkd = true;
          networking.firewall.allowedUDPPorts = [ 23542 ];
          networking.wireguard.interfaces.wg0 = {
            ips = [ "10.23.42.1/32" "fc00::1/128" ];
            listenPort = 23542;

            privateKeyFile = toString (pkgs.writeText "privateKey" wg-snakeoil-keys.peer0.privateKey);

            peers = lib.singleton {
              allowedIPs = [ "10.23.42.2/32" "fc00::2/128" ];

              inherit (wg-snakeoil-keys.peer1) publicKey;
            };
          };
        };
      };

      peer1 = peer {
        ip4 = "192.168.0.2";
        ip6 = "fd00::2";
        extraConfig = {
          boot = lib.mkIf (kernelPackages != null) { inherit kernelPackages; };
          networking.useNetworkd = true;
          networking.wireguard.interfaces.wg0 = {
            ips = [ "10.23.42.2/32" "fc00::2/128" ];
            listenPort = 23542;
            # allowedIPsAsRoutes = false;

            privateKeyFile = toString (pkgs.writeText "privateKey" wg-snakeoil-keys.peer1.privateKey);

            peers = lib.singleton {
              allowedIPs = [ "0.0.0.0/0" "::/0" ];
              endpoint = "192.168.0.1:23542";
              persistentKeepalive = 25;

              inherit (wg-snakeoil-keys.peer0) publicKey;
            };

            # postSetup = let inherit (pkgs) iproute2; in ''
            #   ${iproute2}/bin/ip route replace 10.23.42.1/32 dev wg0
            #   ${iproute2}/bin/ip route replace fc00::1/128 dev wg0
            # '';
          };
        };
      };
    };

    testScript = ''
      start_all()

      # TODO: this doesn't work for networkd
      # TODO: update all the tests accordingly
      peer0.wait_for_unit("systemd-networkd-wait-online.service")
      peer1.wait_for_unit("systemd-networkd-wait-online.service")

      peer1.succeed("ping -c5 fc00::1")
      peer1.succeed("ping -c5 10.23.42.1")
    '';
  }
)
