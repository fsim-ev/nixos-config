# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, lib, pkgs, ... }:
{
	imports = [
		# Include the results of the hardware scan.
		./hardware-configuration.nix
		# Define user accounts. Don't forget to set a password with ‘passwd’.
		./users/bib48218.nix
		./users/fla34149.nix
		./users/fsim.nix
		./users/kum31796.nix
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

	services = rec {

		# Nextcloud
		nextcloud = {
			enable = true;
			package = pkgs.nextcloud21;
			hostName = "cloud.fsim-ev.de";
			config = {
				dbtype = "pgsql";
				dbhost = "/run/postgresql"; # nextcloud will add /.s.PGSQL.5432 by itself
				adminuser = "nixi";
				adminpassFile = toString ./secrets/nextcloud-admin-pass;
				overwriteProtocol = "https";
			};
		};

		# Web server
		nginx = {
			enable = true;
			recommendedGzipSettings = true;
			recommendedOptimisation = true;
			recommendedProxySettings = true;
			recommendedTlsSettings = true;
			clientMaxBodySize = "256m";

			virtualHosts = {
				"fsim.oth-regensburg.de" = {
					default = true;
					forceSSL = true;
					enableACME = true;
				};
				"fsim.othr.de" = {
					forceSSL = true;
					enableACME = true;
					globalRedirect = "fsim.oth-regensburg.de";
				};
				"fsim.hs-regensburg.de" = {
					forceSSL = true;
					enableACME = true;
					globalRedirect = "fsim.oth-regensburg.de";
				};

				# Nextcloud
				"${config.services.nextcloud.hostName}" = {
					forceSSL = true;
					enableACME = true;
				};

				# Zulip
				"chat.fsim-ev.de" = {
					forceSSL = true;
					enableACME = true;
					locations."/" = {
						proxyPass = "http://localhost:8001";
					};
				};
			};
		};

		# Database
		postgresql = {
			enable = true;
			package = pkgs.postgresql_12;
			ensureDatabases = [ config.services.nextcloud.config.dbname ];
			ensureUsers = [
				{
					name = config.services.nextcloud.config.dbuser;
					ensurePermissions."DATABASE ${config.services.nextcloud.config.dbname}" = "ALL PRIVILEGES";
				}
			];
		};
	};

	# NextCloud: ensure that postgres is running *before* running the setup
	systemd.services."nextcloud-setup" = {
		requires = ["postgresql.service"];
		after = ["postgresql.service"];
	};

	security.acme = {
		# Let's Encrypt Certificate Management
		email = "fachschaft_im@oth-regensburg.de";
		acceptTerms = true;
	};

	virtualisation.docker.enable = true;

	virtualisation.oci-containers.containers = rec {
		chat = {
			image = "zulip/docker-zulip:4.3-0";
			dependsOn = [ "chat-db" "chat-cache" "chat-mqueue" ];
			# hack
			cmd = [ "/bin/sh" "-c" "/home/zulip/deployments/current/scripts/zulip-puppet-apply -f && entrypoint.sh app:run" ];
			environment = {
				MANUAL_CONFIGURATION = "true";
				#LINK_SETTINGS_TO_DATA = "true";

				# Zulip being retarded...
				SETTING_EXTERNAL_HOST = "chat.fsim-ev.de";
				SETTING_ZULIP_ADMINISTRATOR = "fachschaft_im@oth-regensburg.de";
				SSL_CERTIFICATE_GENERATION = "self-signed";

				SECRETS_postgres_password = lib.fileContents ./secrets/zulip-db-pass;
				SECRETS_redis_password = lib.last (lib.splitString " " (lib.fileContents ./secrets/zulip-redis.conf));
				SECRETS_rabbitmq_password = lib.fileContents ./secrets/zulip-mq-pass;
			};
			volumes = [
				"/var/lib/zulip:/data"
				(toString ./services/zulip/zulip.conf  + ":/etc/zulip/zulip.conf")
				(toString ./services/zulip/settings.py + ":/etc/zulip/settings.py")
				(toString ./secrets/zulip              + ":/etc/zulip/zulip-secrets.conf")
			];
			extraOptions = [ "--network=container:chat-db" ];
		};
		chat-db = {
			image = "zulip/zulip-postgresql:10";
			environment = {
				POSTGRES_DB = "zulip";
				POSTGRES_USER = "zulip";
				POSTGRES_PASSWORD = chat.environment.SECRETS_postgres_password;
			};
			volumes = [
				"/var/lib/zulip/postgresql/data:/var/lib/postgresql/data:rw"
			];
			ports = [ "8001:80" ]; # for 'chat' container
		};
		chat-cache = {
			image = "redis:alpine";
			dependsOn = [ "chat-db" ];
			cmd = [ "/etc/redis.conf" ];
			volumes = [
				"/var/lib/zulip/redis:/data:rw"
				(toString ./secrets/zulip-redis.conf + ":/etc/redis.conf")
			];
			extraOptions = [ "--network=container:chat-db" ];
		};
		chat-mqueue = {
			image = "rabbitmq:3.7.7";
			dependsOn = [ "chat-db" ];
			environment = {
				RABBITMQ_DEFAULT_USER = "zulip";
				RABBITMQ_DEFAULT_PASS = chat.environment.SECRETS_rabbitmq_password;
			};
			volumes = [
				"/var/lib/zulip/rabbitmq:/var/lib/rabbitmq:rw"
			];
			extraOptions = [ "--network=container:chat-db" ];
		};
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
