# Test NixOS configuration for validating the mdns-filter module
{ pkgs, ... }: {
  services.mdns-filter = {
    enable = true;
    interfaces = [ "eth0" "wlan0" ];
    defaultAction = "allow";
    rules = {
      deny-iot-subnet = {
        match = { src_ip = "192.168.10.0/24"; };
        action = "deny";
      };
      allow-chromecasts = {
        match = {
          instance = "Google-Cast-*";
          service = "_googlecast._tcp";
        };
        matchMode = "all";
        action = "allow";
        log = "info";
      };
    };
  };

  # Minimal config to make NixOS evaluation happy
  boot.loader.grub.device = "nodev";
  fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
  system.stateVersion = "24.05";
}
