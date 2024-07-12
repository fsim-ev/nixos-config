{ config, pkgs, ... }:
with pkgs.lib; {
  users.users = {
    # Non-personal administrator
    fsim = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
    };
    # Student accounts
    bib48218 = {
      isNormalUser = true;
      extraGroups = [ "wheel" "nextcloud" ];
      shell = pkgs.fish;
      openssh.authorizedKeys.keyFiles = [ ./ssh/bib48218.pub ];
    };
    fla34149 = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keyFiles = [ ./ssh/fla34149.pub ];
    };
    uta36888 = {
      isNormalUser = true;
      extraGroups = [ "wheel" "nextcloud" ];
      shell = pkgs.fish;
      openssh.authorizedKeys.keys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFmLpfmWBpi1ACI7q/9Rr6QNjy2ntvYRrvIcoXiTleMi engi"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKy1pBbnSgIihWZg4PozI26NUTARrBVrziaV2fXNNZY9 hyperspace"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxvuuNWDRxO3LuyQX2MaD2NYygqWN5wMVCClSPb4M0Q base"
      ];
    };

    laq33610 = {
      isNormalUser = true;
      extraGroups = [ "nextcloud" ];
      shell = pkgs.bash;
      openssh.authorizedKeys.keyFiles = [ ./ssh/laq33610.pub ];
    };
    beo45216 = {
      isNormalUser = true;
      extraGroups = [ "nextcloud" ];
      shell = pkgs.zsh;
      openssh.authorizedKeys.keyFiles = [ ./ssh/beo45216.pub ];
    };
  };
}
