{ config, pkgs, ... }:
with pkgs.lib; {
	users.users = {
		kum31796 = {
			isNormalUser = true;
			extraGroups = [ "nextcloud" ];
			openssh.authorizedKeys.keyFiles = [
				./ssh/kum31796.pub
				./ssh/kum31796_2.pub
			];
		};
	};
}
