# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, lib, pkgs, ... }:

with lib;

let
  fsimMail = "fachschaft_im@oth-regensburg.de";
  mainDomain = "fsim-ev.de";
  appSpecs = {
    zulip = {
      domain = "chat.fsim-ev.de";
      proxyPort = 8001;
    };
    nextcloud = {
      domain = "cloud.fsim-ev.de";
      proxyPort = null;
    };
    hedgedoc = {
      domain = "pad.fsim-ev.de";
      proxyPort = 3003;
    };
  };
in
{
  imports = [
    # Include the results of the hardware scan.
    ./hardware-configuration.nix
    # Define user accounts. Don't forget to set a password with ‘passwd’.
    ./users/users.nix
  ];

  containers.temp-pg.config.services.postgresql = {
    enable = true;
    package = pkgs.postgresql_13;
    ## set a custom new dataDir
    # dataDir = "/some/data/dir";
  };

  environment.systemPackages = with pkgs;
    let newpg = config.containers.temp-pg.config.services.postgresql;
    in [ # PostgreSQL upgrade script
      (writeScriptBin "upgrade-pg-cluster" ''
        set -x
        export OLDDATA="${config.services.postgresql.dataDir}"
        export NEWDATA="${newpg.dataDir}"
        export OLDBIN="${config.services.postgresql.package}/bin"
        export NEWBIN="${newpg.package}/bin"

        install -d -m 0700 -o postgres -g postgres "$NEWDATA"
        cd "$NEWDATA"
        sudo -u postgres $NEWBIN/initdb -D "$NEWDATA"

        systemctl stop postgresql    # old one

        sudo -u postgres $NEWBIN/pg_upgrade \
          --old-datadir "$OLDDATA" --new-datadir "$NEWDATA" \
          --old-bindir $OLDBIN --new-bindir $NEWBIN \
          "$@"
      '')

    htop
    nano
    vim
    lf
    curl
    wget
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
      package = pkgs.nextcloud22;
      hostName = appSpecs.nextcloud.domain;
      config = {
        dbtype = "pgsql";
        dbhost = "/run/postgresql"; # nextcloud will add /.s.PGSQL.5432 by itself
        adminuser = "nixi";
        adminpassFile = toString ./secrets/nextcloud-admin-pass;
        overwriteProtocol = "https";
        defaultPhoneRegion = "DE";
      };
      caching = {
        apcu = true;
        redis = true;
      };
      phpOptions = mkOptionDefault {
        # See: https://docs.nextcloud.com/server/22/admin_manual/configuration_server/caching_configuration.html#id1
        "apc.cli_enable" = "1";
      };
      maxUploadSize = "16G";
    };

    # Web server
    nginx = {
      enable = true;
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      clientMaxBodySize = "256m";

      virtualHosts =
        let
          sslConfig = { forceSSL = true; enableACME = true; };
        in
        mkMerge [
          { default = { default = true; globalRedirect = mainDomain; }; }
          (genAttrs # Generate vHosts for all OTH domains
            (pipe [ "oth-regensburg" "othr" "hs-regensburg" ] [
              (map (x: "fsim." + x + ".de"))
              # Prevent circular redirect
              (filter (x: x != mainDomain))
            ])
            (domain: sslConfig // { globalRedirect = mainDomain; }))
          (mapAttrs' # Generate proxy vHosts for services
            (_: { domain, proxyPort, ... }:
              let cfg = (optionalAttrs (proxyPort != null)
                { locations."/".proxyPass = "http://localhost:${toString proxyPort}"; });
              in nameValuePair "${domain}" (sslConfig // cfg))
            appSpecs)
          ({
            "examia.de" = sslConfig // {
              serverAliases = ["www.examia.de"];
              root = "/var/lib/www/examia.de";
              locations."/".index = "index.php";
              extraConfig = ''
                index index.php index.html /index.php$request_uri;
                # Disallow senible phpbb files
                location ~ /(config\.php|common\.php|cache|files|images/avatars/upload|includes|store) {
                  deny all;
                  return 403;
                }

                location ~ /\.git {
                  deny all;
                }

                # Disallow accessing .htaccess files
                location ~/\.ht {
                  deny all;
                }

                location ~* \.(gif|jpe?g|png|css)$ {
                  expires 30d;
                }

                location ~ \.php$ {
                  include ${config.services.nginx.package}/conf/fastcgi.conf;
                  try_files $uri =404;
                  fastcgi_pass unix:/run/phpfpm/websrv.sock;
                  fastcgi_split_path_info ^(.+\.php)(/.*)$;
                  fastcgi_param PATH_INFO $fastcgi_path_info;
                  fastcgi_index index.php;
                  fastcgi_param PHP_VALUE "
                    upload_max_filesize = 1G
                    max_execution_time = 60
                    max_input_time = 120
                    post_max_size = 1G
                  ";
                }

                location /app.php {
                  try_files $uri $uri/ /app.php?$query_string;
                }

                location /install/app.php {
                  try_files $uri $uri/ /install/app.php?$query_string;
                }
              '';
            };
          })
        ];
    };

    # Hedgedoc
    hedgedoc = {
      enable = true;
      configuration = {
        domain = appSpecs.hedgedoc.domain;
        port = appSpecs.hedgedoc.proxyPort;
        protocolUseSSL = true;
        dhParamPath = null;
        hsts.enable = true;
        allowOrigin = [
          appSpecs.hedgedoc.domain
        ];
        csp = {
          enable = true;
          upgradeInsecureRequest = "auto";
          addDefaults = true;
        };

        db = {
          dialect = "postgres";
          host = "/run/postgresql";
          username = "hedgedoc";
          database = "hedgedoc";
        };

        allowAnonymous = false;
        defaultPermission = "private"; # Privacy first
        allowFreeURL = false; # for even more privacy

        allowGravatar = false;

        email = false;
        allowEmailRegister = false;
        ldap = {
          url = "ldaps://dc2.hs-regensburg.de";
          providerName = "NDS Kennung";
          bindDn = "";
          bindCredentials = "";
          searchBase = "ou=HSR,dc=hs-regensburg,dc=de";
          searchAttributes = [ "displayName" "mail" "cn" ];
          searchFilter = "(cn={{username}})";
          userNameField = "displayName";
          useridField = "cn";
          tlsca="";
        };
      };
    };

    # Database
    postgresql = {
      enable = true;
      package = pkgs.postgresql_13;
      ensureDatabases = [ config.services.nextcloud.config.dbname ];
      ensureUsers = [
        {
          name = config.services.nextcloud.config.dbuser;
          ensurePermissions."DATABASE ${config.services.nextcloud.config.dbname}" = "ALL PRIVILEGES";
        }
        {
          name = config.services.hedgedoc.configuration.db.username;
          ensurePermissions."DATABASE ${config.services.hedgedoc.configuration.db.database}" = "ALL PRIVILEGES";
        }
      ];
    };
    # Database for Examia
    mysql = {
      enable = true;
      package = pkgs.mariadb;
      ensureDatabases = [ "examia_phpbb" ];
      ensureUsers = [
        {
          name = "examia_phpbb";
          ensurePermissions."examia_phpbb.*" = "ALL PRIVILEGES";
          # Don't forget to set password for 'examia_phpbb@localhost'
        }
      ]; 
    };
    
    # PHP
    phpfpm = {
      phpOptions = ''
        date.timezone = "Europe/Berlin"
      '';
      pools = {
        # Generic PHP pool
        # Used by:
        # - Examia
        websrv = {
          user = "nginx";
          group = "nginx";
          settings = {
            "pm" = "ondemand";
            "pm.max_children" = 10;
            "pm.max_requests" = 500;
            # dump hacks
            "listen.mode" = "0600";
            "listen.owner" = config.services.nginx.user;
            "listen.group" = config.services.nginx.group;
          };
        };
      };
    };  

    # Cache
    # - Nextcloud: File locking
    redis.enable = true;

    # Monitoring (http://fsim.othr.de:19999/)
    netdata.enable = true;
  };

  # NextCloud: ensure that postgres is running *before* running the setup
  systemd.services."nextcloud-setup" = {
    requires = [ "postgresql.service" ];
    after = [ "postgresql.service" ];
  };

  security.acme = {
    # Let's Encrypt Certificate Management
    email = fsimMail;
    acceptTerms = true;
  };

  virtualisation.docker.enable = true;

  virtualisation.oci-containers.containers = rec {
    chat = {
      image = "zulip/docker-zulip:5.1-0";
      dependsOn = [ "chat-db" "chat-cache" "chat-mqueue" ];
      # hack
      cmd = [ "/bin/sh" "-c" "/home/zulip/deployments/current/scripts/zulip-puppet-apply -f && entrypoint.sh app:run" ];
      environment = {
        MANUAL_CONFIGURATION = "true";
        #LINK_SETTINGS_TO_DATA = "true";

        # Zulip being retarded...
        SETTING_EXTERNAL_HOST = appSpecs.zulip.domain;
        SETTING_ZULIP_ADMINISTRATOR = fsimMail;
        SSL_CERTIFICATE_GENERATION = "self-signed";

        SECRETS_postgres_password = lib.fileContents ./secrets/zulip-db-pass;
        SECRETS_redis_password = lib.last (lib.splitString " " (lib.fileContents ./secrets/zulip-redis.conf));
        SECRETS_rabbitmq_password = lib.fileContents ./secrets/zulip-mq-pass;
      };
      volumes = [
        "/var/lib/zulip:/data"
        (toString ./services/zulip/zulip.conf + ":/etc/zulip/zulip.conf")
        (toString ./services/zulip/settings.py + ":/etc/zulip/settings.py")
        (toString ./secrets/zulip + ":/etc/zulip/zulip-secrets.conf")
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

  # FSIM room tunnel
  networking.wireguard = {
    enable = true;
    interfaces."wg0" = {
      privateKeyFile = toString ./secrets/wireguard-tunnel.key;
      generatePrivateKeyFile = true;
      listenPort = 4422;
      ips = [ "10.24.1.1/32" ];
      peers = [{
        allowedIPs = [ "10.24.1.2/32" "10.24.0.0/24" ];
        publicKey = "oOhxVotHhrno8lw4NazqmCYFHXOQ2zcSFNAI0Pf8mgE=";
      }];
    };
  };

  ###########################################################################
  # DANGER ZONE

  security.sudo.enable = true;
  services.openssh = {
    enable = true;
    passwordAuthentication = false;
  };
  services.sshguard.enable = true;

  networking = {
    hostName = "im-srv-004";
    hosts = {
      "127.0.1.1" = [
        "im-srv-004"
        "im-srv-004.hs-regensburg.de"
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
    tmpOnTmpfs = true;
  };

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "21.11"; # Did you read the comment?
}
