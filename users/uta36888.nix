{ config, pkgs, ... }:
with pkgs.lib; {
	users.users = {
		uta36888 = {
			isNormalUser = true;
			extraGroups = [ "wheel" "nextcloud" ];
			shell = pkgs.fish;
			openssh.authorizedKeys.keyFiles = [ ./ssh/uta36888.pub ];
		};
	};
}
