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
    kum31796 = {
      isNormalUser = true;
      extraGroups = [ "nextcloud" ];
      openssh.authorizedKeys.keyFiles = [
        ./ssh/kum31796.pub
        ./ssh/kum31796_2.pub
      ];
    };
    uta36888 = {
      isNormalUser = true;
      extraGroups = [ "wheel" "nextcloud" ];
      shell = pkgs.fish;
      openssh.authorizedKeys.keyFiles = [ ./ssh/uta36888.pub ];
    };
  };
}
