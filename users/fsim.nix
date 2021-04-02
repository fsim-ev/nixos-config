{ config, pkgs, ... }:
with pkgs.lib; {
	users.users = {
		fsim = {
			isNormalUser = true;
			extraGroups = [ "wheel" ];
		};
	};
}
