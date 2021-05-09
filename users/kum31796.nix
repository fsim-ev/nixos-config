{ config, pkgs, ... }:
with pkgs.lib; {
	users.users = {
		kum31796 = {
			isNormalUser = true;
			openssh.authorizedKeys.keyFiles = [ ./ssh/kum31796.pub ];
		};
	};
}
