# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
	imports = [
		# Include the results of the hardware scan.
		./hardware-configuration.nix
	];

	environment.systemPackages = with pkgs; [
		htop
		nano vim
		curl wget
	];

	programs = {
		fish.enable = true;
		less.enable = true;
		tmux.enable = true;
	};

	###########################################################################
	# DANGER ZONE

	# Define a user account. Don't forget to set a password with ‘passwd’.
	users = {
		users = {
			fsim = {
				isNormalUser = true;
				extraGroups = [ "wheel" ];
			};
			bib48218 = {
				isNormalUser = true;
				extraGroups = [ "wheel" ];
				shell = pkgs.fish;
				openssh.authorizedKeys.keys = [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCpcUE+pheherwiudaf8vEjJn0Ey9F+ZjwJtNEPpYPcK0a5om06EgcsVi39ggZCNeX7lyK09pqzJKgMTlfyQWWv4U5w0hBEBresgfOxHTAc+MzJ+dfHzUqeMNTKUFP7sZwDjFboshRmZRd7FX4bIcLmbe1TxWBz/XAr7g7lOD7hZJOFj/b8vlVbSZjOdZ23vIdf9RldY2ULdDK/EuHE5fFRbX6vVmidYjHl8CX7VPKkT3VhiXGhl2T7DEAScpRs8dOztY8sVeK5GLW78ozVbessODi3ErziejpygfRJ1JhslQa7Vwf/Lsd5RS6vSYafvLYCXT7scvbGE+gFmXtg9wR7Q8Z0i42JAUTDZdqpJ09Qp6slh/fWQ65Ym3lHcYHt/lqksUOBX+t8uF+o3ST6PGqoFxDeYY7kvyMgRjqvnsNyswUM179BbJrccgQPUbpHZO76l9+tYPRUF4sGdiVADbgMp6PXqt6wax+vlIb3CBj4gJCkZxf6jrK2LfqwL86NZIOe0RX1CegXJH6rYFTvHe7PzdbudupojmmpJWF/imD6ULm9W0tUsWJLpPzMnfnpbqmhMYRRRUBYP7Mf4tBCaxc2XK9VGQzZsmsa6Yf4KqOTOoz64fnceLye3O+CB9/JQ0t7HYOoSPI/X4KqNbEogAa5+uw/3/wIM1acH3YdQM1ufw==" ];
			};
			uta36888 = {
				isNormalUser = true;
				extraGroups = [ "wheel" ];
				shell = pkgs.fish;
				openssh.authorizedKeys.keys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILdsma74LYn5VdICUm1KgPte4rO563sWXJQfoVGGdfe6"];
			};
			fla34149 = {
				isNormalUser = true;
				extraGroups = [ "wheel" ];
				openssh.authorizedKeys.keys = [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDPyzjmyJS5JCKD2Y9Rxl/gD4UfPRxrAl1gfVQ1+iVUbKLp3BARRAbUgVSGv2WY/Vguv6hqt3+SgGSN1iXyKTTO78NanhIDTVTgyWBIj2uJsFzj9NF5r3Q5V6YknqjOUFYpi/mlOmroQ3G4gsol2CON/lLbFiEX+hrJycc4srt4ruKOrSV9Kgh8pWtsdYw+vIqM8bblhuu5JRezNd08cuQu5hV59zJaIJRWNWmJ1dmD3Ci6ODfz7jZU1nI0lPkR88b1f1SAmMgTj91aIw4MrwkUL9sp/MGtrGgBTXJ87ba18Xd2pp4yPeJ5E0qaHQWNicYtEGV3or+sRr6PmLR+DLw4/BlO06CMulgIGDfOz5/4kAMEHYXf1BMDisJlAFlAaynkcI3a80HdEsJcu471ZRTzdJFRCRPf2IAAAZq1qAVySajWOc8VG6cmO8wFwI9WFLMdw8QYU5TK/8nNwqgip53nEJJhq76WoXWMNjPeiCiXQrpoEj16m7GX/m90Ll8x8JFUxZuzONg/n+Qj8PnNbFqPKU+Tc691kwgOzBkCwrCgMaQ+ihiNYzEaYg/h0e2n/SEb1/R2l9iw8K3ApnU9Hl4Hg01RjPfOrKimysnuMT2Ej9DsQcEukK42c9BD88MTPAD/YOKunnYisfnymdMze0cq2vq0Y60oqCiPtqGuvF5yBQ=="];
			};
		};
	};

	security.sudo.enable = true;
	services.openssh = {
		enable = true;
		passwordAuthentication = false;
	};

	networking = {
		hostName = "im-srv-004";
		hosts = {
			"127.0.1.1" = [
				"im-srv-004" "im-srv-004.hs-regensburg.de"
			];
		};

		# The global useDHCP flag is deprecated, therefore explicitly set to false here.
		useDHCP = false;
		interfaces.eno1.useDHCP = true;

		firewall.enable = false;
	};

	time.timeZone = "Europe/Berlin";

	# Select internationalization properties.
	i18n.defaultLocale = "en_US.UTF-8";
	console = {
		font = "Lat2-Terminus16";
		keyMap = "de";
	};

	boot = {
		# Use the GRUB 2 boot loader.
		loader.grub = {
			enable = true;
			version = 2;
			device = "/dev/sda";
		};
		kernelPackages = pkgs.linuxPackages_5_10;
		initrd.network.ssh = {
			enable = true;
			port = 22;
		};
	};

	# This value determines the NixOS release from which the default
	# settings for stateful data, like file locations and database versions
	# on your system were taken. It‘s perfectly fine and recommended to leave
	# this value at the release version of the first install of this system.
	# Before changing this value read the documentation for this option
	# (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
	system.stateVersion = "20.09"; # Did you read the comment?

}

