{ config, pkgs, ... }:
with pkgs.lib; {
	users.users = {
		bib48218 = {
			isNormalUser = true;
			extraGroups = [ "wheel" "nextcloud" ];
			shell = pkgs.fish;
			openssh.authorizedKeys.keyFiles = [ ./ssh/bib48218.pub ];
		};
	};
}
