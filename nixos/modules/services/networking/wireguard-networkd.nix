{ config, lib, options, ... }:

let
  # TODO: reorganize by import source or whatever it is
  inherit (lib) mkOption mdDoc types versionAtLeast literalExpression filterAttrs nameValuePair mkIf attrNames mapAttrs mapAttrs' flip mapAttrsToList concatMap concatLists;
in
{

  options = {
    networking.wireguard = {
      useNetworkd = mkOption {
        # TODO
        description = mdDoc ''
        Whether to use networkd as the network configuration backend instead of
        the legacy script-based system for Wireguard interfaces.

        This is enabled by default for systems with `stateVersion >= 24.05`.
        
        ::: {.warning}
        Use caution when enabling this option on a system with an existing
        Wireguard configuration. The networkd backend may have subtly different
        behavior than the legacy script-based system. 
        :::
        '';
        type = types.bool;
        # networkd will be enabled for Wireguard by default in systems created with 24.05 or later.
        default = config.networking.useNetworkd || (versionAtLeast config.system.stateVersion "24.05");
        defaultText = literalExpression "config.networking.useNetworkd || (versionAtLeast config.system.stateVersion \"24.05\")";
      };
    };
  };

  config = let

    cfg = config.networking.wireguard;

    removeNulls = filterAttrs (_: v: v != null);

    # TODO: double-check how we should name these netdevs
    generateNetdev = name: interface: nameValuePair "10-${name}" {
      netdevConfig = removeNulls {
        Kind = "wireguard";
        Name = name;

        # TODO: update description
        MTUBytes = interface.mtu;
      };
      wireguardConfig = removeNulls {
        # TODO: update privateKeyFile description with warning about readable by systemd-network user
        PrivateKeyFile = interface.privateKeyFile; # TODO: assert that this exists, one way or the other
        ListenPort = interface.listenPort;
        FirewallMark = interface.fwMark;

        # TODO: update description of 'table' option for precision (include null in type)
        RouteTable = if interface.allowedIPsAsRoutes then interface.table else null;
        RouteMetric = interface.metric;
      };
      wireguardPeers = map generateWireguardPeer interface.peers;
    };

    generateWireguardPeer = peer: {
      # TODO
      wireguardPeerConfig = removeNulls {
        PublicKey = peer.publicKey;

        # TODO: double-check type, since this requires an absolute path
        PresharedKeyFile = peer.presharedKeyFile;

        AllowedIPs = peer.allowedIPs;

        # TODO: update option description for accuracy
        Endpoint = peer.endpoint;

        PersistentKeepalive = peer.persistentKeepalive;
      };

      # TODO: see about adding these in:
      # - RouteTable
      # - RouteMetric
    };

    generateNetwork = name: interface: {
      matchConfig.Name = name;
      # TODO: when useNetworkd, validate that IPs have subnet length things
      address = interface.ips;
    };

    # TODO: make sure generatePrivateKeyFile is still enabled (it should be compatible)

  in mkIf (cfg.enable && cfg.useNetworkd) {
    # TODO: assertions
    assertions =
      [
        # Top-level assertions
      ]
      ++ concatLists (flip mapAttrsToList cfg.interfaces (name: interface: [
        # Interface assertions
        {
          assertion = interface.privateKey == null;
          message = "networking.wireguard.interfaces.${name}.privateKey is not supported with networking.wireguard.useNetworkd. Use privateKeyFile instead.";
        }
        {
          assertion = interface.preSetup == "";
          message = "networking.wireguard.interfaces.${name}.preSetup is not supported with networking.wireguard.useNetworkd.";
        }
        {
          assertion = interface.postSetup == "";
          message = "networking.wireguard.interfaces.${name}.postSetup is not supported with networking.wireguard.useNetworkd.";
        }
        {
          assertion = interface.postShutdown == "";
          message = "networking.wireguard.interfaces.${name}.postShutdown is not supported with networking.wireguard.useNetworkd.";
        }
        {
          assertion = interface.socketNamespace == null;
          message = "networking.wireguard.interfaces.${name}.socketNamespace is not (yet) supported with networking.wireguard.useNetworkd.";
        }
        {
          assertion = interface.interfaceNamespace == null;
          message = "networking.wireguard.interfaces.${name}.interfaceNamespace is not (yet) supported with networking.wireguard.useNetworkd.";
        }
      ]
      ++ flip concatMap interface.peers (peer: [
        # Peer assertions
        {
          assertion = peer.presharedKey == null;
          message = "networking.wireguard.interfaces.${name}.peers[].presharedKey is not supported with networking.wireguard.useNetworkd. Use presharedKeyFile instead.";
        }
        {
          # TODO: link to upstream systemd issues?
          assertion = peer.dynamicEndpointRefreshSeconds == 0;
          message = "networking.wireguard.interfaces.${name}.peers[].dynamicEndpointRefreshSeconds is not supported with networking.wireguard.useNetworkd.";
        }
        {
          # TODO: link to upstream systemd issues?
          assertion = peer.dynamicEndpointRefreshRestartSeconds == null;
          message = "networking.wireguard.interfaces.${name}.peers[].dynamicEndpointRefreshRestartSeconds is not supported with networking.wireguard.useNetworkd.";
        }
      ])));

    systemd.network = {
      enable = true; # TODO: should we do this here or rely on it coming from elsewhere?
      netdevs = mapAttrs' generateNetdev cfg.interfaces;
      networks = mapAttrs generateNetwork cfg.interfaces;
    };

    # TODO: should we even do this?
    # TODO: do it always, or only with networkd?
    networking.networkmanager.unmanaged = attrNames cfg.interfaces;
  };
}
