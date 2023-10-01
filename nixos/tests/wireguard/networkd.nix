import ../make-test-python.nix ({ pkgs, lib, kernelPackages ? null, ...} :
  let
    wg-snakeoil-keys = import ./snakeoil-keys.nix;
    peer = (import ./make-peer.nix) { inherit lib; };
  in
  {
    name = "wireguard-networkd";
    meta = with pkgs.lib.maintainers; {
      maintainers = [ majiir ];
    };

    nodes = {
      peer0 = peer {
        ip4 = "192.168.0.1";
        ip6 = "fd00::1";
        extraConfig = {
          boot = lib.mkIf (kernelPackages != null) { inherit kernelPackages; };
          networking.firewall.allowedUDPPorts = [ 23542 ];
          # environment.systemPackages = [ pkgs.wireguard-tools ];
          systemd.network = {
            enable = true;
            netdevs."10-wg0" = {
              netdevConfig = {
                Kind = "wireguard";
                Name = "wg0";
              };
              wireguardConfig = {
                ListenPort = 23542;
                PrivateKeyFile = pkgs.writeText "test-privateKey" wg-snakeoil-keys.peer0.privateKey;
                RouteTable = "main";
              };
              wireguardPeers = [
                {
                  wireguardPeerConfig = {
                    AllowedIPs = [ "10.23.42.2/32" "fc00::2/128" ];
                    PublicKey = wg-snakeoil-keys.peer1.publicKey;
                  };
                }
              ];
            };
            networks.wg0 = {
              matchConfig.Name = "wg0";
              address = [ "10.23.42.1/32" "fc00::1/128" ];
            };
          };
        };
      };

      peer1 = peer {
        ip4 = "192.168.0.2";
        ip6 = "fd00::2";
        extraConfig = {
          boot = lib.mkIf (kernelPackages != null) { inherit kernelPackages; };
          # environment.systemPackages = [ pkgs.wireguard-tools ];
          systemd.network = {
            enable = true;
            netdevs."10-wg0" = {
              netdevConfig = {
                Kind = "wireguard";
                Name = "wg0";
              };
              wireguardConfig = {
                ListenPort = 23542;
                PrivateKeyFile = pkgs.writeText "test-privateKey" wg-snakeoil-keys.peer1.privateKey;
                RouteTable = "main";
              };
              wireguardPeers = [
                {
                  wireguardPeerConfig = {
                    AllowedIPs = [ "0.0.0.0/0" "::/0" ];
                    PublicKey = wg-snakeoil-keys.peer0.publicKey;
                    Endpoint = "192.168.0.1:23542";
                    PersistentKeepalive = 25;
                  };
                }
              ];
            };
            networks.wg0 = {
              matchConfig.Name = "wg0";
              address = [ "10.23.42.2/32" "fc00::2/128" ];
            };
          };
        };
      };
    };

    testScript = ''
      start_all()

      peer0.wait_for_unit("network-online.target")
      peer1.wait_for_unit("network-online.target")

      peer1.succeed("ping -c5 fc00::1")
      peer1.succeed("ping -c5 10.23.42.1")
    '';
  }
)
