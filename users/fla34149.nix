{ config, pkgs, ... }:
with pkgs.lib; {
	users.users = {
		fla34149 = {
			isNormalUser = true;
			extraGroups = [ "wheel" ];
			openssh.authorizedKeys.keyFiles = [ ./ssh/fla34149.pub ];
		};
	};
}
