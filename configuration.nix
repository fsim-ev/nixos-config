# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
	imports = [
		# Include the results of the hardware scan.
		./hardware-configuration.nix
		# Define a user account. Don't forget to set a password with ‘passwd’.
		./users/bib48218.nix
		./users/fla34149.nix
		./users/fsim.nix
		./users/uta36888.nix
	];

	environment.systemPackages = with pkgs; [
		htop
		nano vim
		curl wget
		git
	];

	programs = {
		fish.enable = true;
		less.enable = true;
		tmux.enable = true;
	};

	###########################################################################
	# DANGER ZONE

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

