self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.mobile-rc;
  mobileRcPkg = self.packages.${pkgs.stdenv.hostPlatform.system}.mobile-rc;

  controlAccessPkg = pkgs.runCommand "mobile-rc-control-access"
    {
      nativeBuildInputs = [ pkgs.makeWrapper ];
    }
    ''
      mkdir -p "$out/bin"
      makeWrapper "${mobileRcPkg}/bin/control-access" "$out/bin/control-access" \
        --set-default MRC_CONFIG_DIR "/var/lib/mobile-rc" \
        --set-default MRC_PORT "${toString cfg.port}"
    '';
in
{
  options.services.mobile-rc = {
    enable = lib.mkEnableOption "Linux Mobile Control Center (Mobile-RC) remote dashboard";

    port = lib.mkOption {
      type = lib.types.port;
      default = 8000;
      description = "TCP port that Mobile-RC listens on.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Optional desktop username (sets MRC_USER). Auto-detected from active user sessions when empty.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open services.mobile-rc.port in the NixOS firewall for LAN smartphone access.";
    };

    disableShell = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Disable Quick Web Terminal command execution (sets MRC_DISABLE_SHELL=1).";
    };

    autoTunnel = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Automatically start the SSH reverse tunnel on boot (sets MRC_AUTO_TUNNEL=1).";
    };

    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "Additional compositor/desktop CLI utilities (e.g. pkgs.niri, pkgs.river-classic, pkgs.wmctrl) exposed in the service PATH.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ controlAccessPkg ];

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.mobile-rc = {
      description = "Mobile-RC Remote Control Center";
      after = [ "network.target" "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      path = with pkgs; [
        python3
        iproute2
        util-linux
        efibootmgr
        openssh
        xdg-utils
        libnotify
        playerctl
        wireplumber
        brightnessctl
        grim
        wl-clipboard
        imagemagick
      ] ++ cfg.extraPackages;

      environment =
        {
          MRC_PORT = toString cfg.port;
          MRC_CONFIG_DIR = "/var/lib/mobile-rc";
        }
        // lib.optionalAttrs (cfg.user != "") { MRC_USER = cfg.user; }
        // lib.optionalAttrs cfg.disableShell { MRC_DISABLE_SHELL = "1"; }
        // lib.optionalAttrs cfg.autoTunnel { MRC_AUTO_TUNNEL = "1"; };

      serviceConfig = {
        Type = "simple";
        User = "root";
        StateDirectory = "mobile-rc";
        StateDirectoryMode = "0700";
        ExecStart = "${mobileRcPkg}/bin/mobile-rc";
        Restart = "always";
        RestartSec = 3;
      };
    };
  };
}
