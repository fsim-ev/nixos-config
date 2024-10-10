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
    wiki-js = {
      domain = "wiki.fsim-ev.de";
      proxyPort = 8002;
    };
    katzensystem = {
      domain = "katzen.fsim-ev.de";
      proxyPort = null;
    };
    passbolt = {
      domain = "pass.fsim-ev.de";
      proxyPort = 8003;
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

  containers.temp-pg.config = {
    system.stateVersion = "22.11";
    services.postgresql = {
      enable = true;
      package = pkgs.postgresql_14;
      ## set a custom new dataDir
      # dataDir = "/some/data/dir";
    };
  };

  # To use FFmpeg with libfdk_aac
  nixpkgs.config.allowUnfree = true;

  environment.systemPackages = with pkgs;
    let
      newpg = config.containers.temp-pg.config.services.postgresql;
      ffmpeg = ffmpeg-full.override {
        nonfreeLicensing = true;
        fdkaacExtlib = true;
        ffplayProgram = false;
        ffprobeProgram = false;
        qtFaststartProgram = false;
      };
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

    #ffmpeg
    htop btop
    nano vim helix
    lf
    curl wget
    git
    pandoc
    
    # for Borg
    mariadb
  ];

  programs = {
    fish.enable = true;
    zsh.enable = true;
    less.enable = true;
    tmux.enable = true;
  };

  services = rec {

    # Engel-/Katzensystem
    engelsystem = {
      enable = true;
      domain = appSpecs.katzensystem.domain;
      createDatabase = true;
      # configuration options with explanations can be found at
      # https://github.com/engelsystem/engelsystem/blob/main/config/config.default.php
      config = {
        database = {
    	    database = "engelsystem";
    	    host = "localhost";
    	    username = "engelsystem";
          # password._secret = "/path/to/secret/file";
    	  };
        # api_keys = "";
        maintenance = false;
        app_name = "Kami-Katzensystem";
        # production/development (set development for debugging messages)
        environment = "production";
        # url = "";
        # header_items = "";
        footer_items = {
          # disabling FAQ does not work (why?)
    	    # FAQ = none;
          Contact = "mailto:fachschaft_im@oth-regensburg.de";
          Website = "https://fsim-ev.de";
          Chat = "https://chat.fsim-ev.de";
          Cloud = "https://cloud.fsim-ev.de";
          Pad = "https://pad.fsim-ev.de";
          Wiki = "https://wiki.fsim-ev.de";
    	  };
        faq_text = "deal with it yourself \n I can't help you";
        documentation_url = "https://wiki.fsim-ev.de";
        # email = {
        #   driver = "smtp";
        #   from = {
        #     address = "fachschaft_im@oth-regensburg.de";
        #     name = "Engelsystem";
        #   };
        #   host = "localhost";
        #   port = 587;
        #   encryption = "tls";
        #   username = "mail_username";
        #   password = "mail_password";
        #   sendmail = "/usr/sbin/sendmail -bs";
        # };
        privacy_email = "fachschaft_im@oth-regensburg.de";
        enable_email_goodie = "false";
        # setup_admin_password = "testpasswd"; # funktioniert nicht -> ist "asdfasdf", sofort beim 1. login aendern
        theme = "1";
        themes = {
          # disable themes here
        };
        home_site = "user_shifts";
        # display_news = "20";
        registration_enabled = true;
        # external_registration_url = "https://someURL.here";
        required_user_fields = {
          pronoun = false;
          firstname = false;
          lastname = false;
          tshirt_size = false;
          mobile = false;
          dect = false;
        };
        signup_requires_arrival = false;
        autoarrive = true;
        supporters_can_promote = false;
        signup_advance_hours = 0;
        signup_post_minutes = 0;
        signup_post_fraction = 0;
        last_unsubscribe = 3;
        # password_algorithm = PASSWORD_DEFAULT;
        password_min_length = 6;
        enable_password = false;
        enable_dect = false;
        enable_mobile_show = false;
        username_regex = "/(^\p{L}\p{N}_.-]+)/ui";
        enable_full_name = false;
        display_full_name = false;
        enable_pronoun = false;
        enable_planned_arrival = false;
        enable_force_active = false;
        enable_self_worklog = false;
        goodie_type = "none";
        enable_voucher = false;
        max_freeloadable_shifts = 10;
        # disable_user_view_columns = {};
        timezone = "Europe/Berlin";
        night_shifts = {
          enabled = false;
          start = 0;
          end = 8;
          multiplier = 2;
        };
        voucher_settings = {
          initial_vouchers = 0;
          shifts_per_voucher = 0;
          hours_per_voucher = 2;
          voucher_start = null;
        };
        driving_license_enabled = false;
        ifsg_enabled = false;
        ifsg_light_enabled = false;
        locales = {
          de_DE = "Deutsch";
          en_US = "English";
        };
        default_locale = "de_DE";
        # tshirt_sizes = {
        #   S = "Small Straight-Cut";
        #   S-F = "Small Fitted-Cut";
        #   M = "Medium Straight-Cut";
        #   M-F = "Medium Fitted-Cut";
        #   L    = "Large Straight-Cut";
        #   L-F  = "Large Fitted-Cut";
        #   XL   = "XLarge Straight-Cut";
        #   XL-F = "XLarge Fitted-Cut";
        #   2XL  = "2XLarge Straight-Cut";
        #   3XL  = "3XLarge Straight-Cut";
        #   4XL  = "4XLarge Straight-Cut";
        # };
        # tshirt_link = "";
        enabel_day_of_event = true;
        event_has_day0 = true;
        filter_max_duration = 0;
        session = {
          driver = "pdo";
          name = "session";
          lifetime = 30;
        };
        # trusted_proxies = "127.0.0.0/8";
        add_headers = true;
        headers = {
          X-Content-Type-Options = "nosniff";
          X-Frame-Options = "sameorigin";
          Referrer-Policy = "strict-origin-when-cross-origin";
          # Conent-Security-Policy = ""
          X-XSS-Protection = "1; mode=block";
          # Feature-Policy = "autoplay \'none\'";
        };
        credits = {
          Contribution = "Please just skip this. There is nothing to see here.";
        };
        # var_dump_server = {

        #   hsot = "127.0.0.1";
        #   port = "9912";
        #   enable = false;
        # };
        oauth = {
          sso = {
            name = "Nextcloud";
            client_id = (builtins.readFile ./secrets/engelsystem-clientid);
            client_secret = (builtins.readFile ./secrets/engelsystem-clientsecret);
            url_auth = "https://cloud.fsim-ev.de/apps/oauth2/authorize";
            url_token = "https://cloud.fsim-ev.de/apps/oauth2/api/v1/token";
            url_info = "https://cloud.fsim-ev.de/ocs/v2.php/cloud/user?format=json";
            # scope = "openid";
            id = "ocs.data.id";
            username = "ocs.data.displayname";
            email = "ocs.data.email";
            # first_name = "first-name";
            # last_name = "last-name";
            url = "https://cloud.fsim-ev.de/";
            nested_info = true;
            # hidden = true;
            mark_arrived = true;
            enable_password = false;
            allow_registration = true;
            # groups = "ocs.data.groups";
            # teams = {
            #   IM_Studenten = 1;
            # };
            # admins = {
            #   "IM_Fachschaft_Administratoren" = [ 60 65 80 90 ];
            # };
          };
        };
      };
    };

    # Nextcloud
    nextcloud = {
      enable = true;
      package = pkgs.nextcloud29.overrideAttrs {
        patches = (./patches/nextcloud-remove-notify-nag.patch);
      };
      hostName = appSpecs.nextcloud.domain;
      config = {
        dbtype = "pgsql";
        dbhost = "/run/postgresql"; # nextcloud will add /.s.PGSQL.5432 by itself
        adminuser = "nixi";
        adminpassFile = toString ./secrets/nextcloud-admin-pass;
      };
      settings = {
        overwriteprotocol = "https";
        default_phone_region = "DE";
        default_locale = "de";
	# loglevel = 2;
	# log_type = "syslog";
      };
      caching = {
        apcu = true;
        redis = true;
      };
      maxUploadSize = "16G";
    };

    # Examia
#    discourse = {
#      #enable = true;
#      hostname = "examia.de";
#      secretKeyBaseFile = toString ./secrets/examia-keybase;
#      admin = {
#        email = fsimMail;
#        username = "fsim";
#        fullName = "Fachschaft IM";
#        passwordFile = toString ./secrets/examia-admin-pass;
#      };
#      mail.outgoing = {
#        #serverAddress = "smtp.hs-regensburg.de";
# #port = 587;
#        #username = "fachschaft_im";
#      };
#      plugins = with config.services.discourse.package.plugins; [
#        discourse-ldap-auth
#      ];
#    };

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
      settings = {
        domain = appSpecs.hedgedoc.domain;
        port = appSpecs.hedgedoc.proxyPort;
        protocolUseSSL = true;
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
          bindDn = lib.fileContents ./secrets/hedgedoc-bindDn;
          bindCredentials = lib.fileContents ./secrets/hedgedoc-bindCredentials;
          searchBase = "ou=HSR,dc=hs-regensburg,dc=de";
          searchAttributes = [ "displayName" "mail" "cn" ];
          searchFilter = "(cn={{username}})";
          userNameField = "displayName";
          useridField = "cn";
          tlsca="";
        };
      };
    };
    
    wiki-js = {
      enable = true;
      settings = {
        bindIP = "127.0.0.1";
        port = appSpecs.wiki-js.proxyPort;

        db.host = "localhost";
        db.pass = "$(DB_PASS)";
        db.db = "wiki";
        db.user = "wiki";

        #logLevel = "silly";
      };
      environmentFile = ./secrets/wiki-js-env;
    };
#    dokuwiki.sites."wiki" = {
#      enable = false;
#      disableActions = "register,resendpwd";
#    };

    # Database
    postgresql = {
      enable = true;
      package = pkgs.postgresql_14;
      ensureDatabases = [ 
        config.services.nextcloud.config.dbname 
        config.services.hedgedoc.settings.db.database
        config.services.wiki-js.settings.db.db
      ];
      ensureUsers = [
        {
          name = config.services.nextcloud.config.dbuser;
          ensureDBOwnership = true;
        }
        {
          name = config.services.hedgedoc.settings.db.username;
          ensureDBOwnership = true;
        }
        {
          name = config.services.wiki-js.settings.db.db;
          ensureDBOwnership = true;
        }        
      ];
      settings = {
        log_min_duration_statement = 1000;
        log_min_messages = "LOG";
        #log_statement = "mod";
        log_destination = lib.mkForce "syslog";
        #log_connections = true;
      
        # Based on https://www.pgconfig.org/#/?max_connections=256&pg_version=14&environment_name=WEB&total_ram=64&cpus=8&drive_type=HDD&arch=x86-64&os_type=linux
        # Memory
        shared_buffers = "16GB";
        effective_cache_size = "48GB";
        work_mem = "64MB";
        maintenance_work_mem = "4GB";
        # Checkpoint related
        min_wal_size = "2GB";
        max_wal_size = "3GB";
        # Storage
        random_page_cost = 5;
        effective_io_concurrency = 2;
      };
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
    redis.servers = {
      "nextcloud" = {
        # File lock cache
        enable = true;
        user = "nextcloud";
      };
    };

    # Monitoring (http://fsim.othr.de:19999/)
    netdata.enable = true;

    # Backup
    borgbackup.jobs = {
      "examia" = {
        paths = [
          "/var/lib/www/examia.de"
          "/tmp/db-backup.sql" # Private /tmp
        ];
        exclude = [
          "/var/lib/www/examia.de/cache"
          "*.lock"
        ];
        preHook = ''
          ${mysql.package}/bin/mysqldump --opt examia_phpbb > /tmp/db-backup.sql
        '';
        repo =  "examia@fren.fsim:.";
        encryption = {
          mode = "repokey-blake2";
          passCommand = "cat /etc/nixos/secrets/borg-infra-enc.key";
        };
        environment = { BORG_RSH = "ssh -i /etc/nixos/secrets/borg-fren-append.key"; };
        compression = "auto,zstd";
        doInit = true;
        startAt = "0/6:00:00"; # every 6 hrs
      };

      "zulip" = {
        paths = [
          "/var/lib/zulip/uploads"
          "/var/lib/zulip/backups"
        ];
        preHook = ''
          # type of quotes is important here!
          PODMAN="${pkgs.podman}/bin/podman"
          $PODMAN exec -it chat entrypoint.sh app:backup
	  # getting newest backup tar with ls and head to replace old backup with the new one
	  # borg will use this that backup to do version controlling
	  $PODMAN exec -it chat sh -c \
	      'mv -vTf /data/backups/$(ls -t /data/backups | head -n1) /data/backups/zulip-backup-current.tar.gz'
        '';
        readWritePaths = [ "/var/lib/containers" "/run/libpod" "/run/lock/netavark.lock" ];
        repo =  "zulip@fren.fsim:.";
        encryption = {
          mode = "repokey-blake2";
          passCommand = "cat /etc/nixos/secrets/borg-infra-enc.key";
        };
        environment = { BORG_RSH = "ssh -i /etc/nixos/secrets/borg-fren-append.key"; };
        compression = "auto,zstd";
        doInit = true;
        startAt = "0/6:00:00"; # every 6 hrs
      };

      "nextcloud" = {
        paths = [
          "/var/lib/nextcloud"
        ];
        repo =  "nextcloud@fren.fsim:.";
        encryption = {
          mode = "repokey-blake2";
          passCommand = "cat /etc/nixos/secrets/borg-infra-enc.key";
        };
        environment = { BORG_RSH = "ssh -i /etc/nixos/secrets/borg-fren-append.key"; };
        compression = "auto,zstd";
        doInit = true;
        startAt = "0/6:00:00"; # every 6 hrs
      };

      "hedgedoc" = {
        paths = [
          "/var/lib/hedgedoc"
          "/tmp/db-backup.sql" # Private /tmp
        ];
        preHook = ''
          ${pkgs.sudo}/bin/sudo -u postgres -- ${postgresql.package}/bin/pg_dump -d hedgedoc > /tmp/db-backup.sql
        '';
        repo =  "hedgedoc@fren.fsim:.";
        encryption = {
          mode = "repokey-blake2";
          passCommand = "cat /etc/nixos/secrets/borg-infra-enc.key";
        };
        environment = { BORG_RSH = "ssh -i /etc/nixos/secrets/borg-fren-append.key"; };
        compression = "auto,zstd";
        doInit = true;
        startAt = "0/6:00:00"; # every 6 hrs
      };
      "minecraft" = {
        paths = [
          "/var/lib/minecraft"
        ];
        preHook = ''
          # type of quotes is important here!
          PODMAN="${pkgs.podman}/bin/podman"
          $PODMAN exec -it minecraft /bin/sh -c "
              mc-send-to-console save-off;
              mc-send-to-console save-all flush;
            "
        '';
        postHook = ''
          # type of quotes is important here!
          PODMAN="${pkgs.podman}/bin/podman"
          $PODMAN exec -it minecraft /bin/sh -c "
              mc-send-to-console save-on;
            "
        '';
        readWritePaths = [ "/var/lib/containers" "/run/libpod" "/run/lock/netavark.lock" ];
        repo =  "minecraft@fren.fsim:.";
        encryption.mode = "none";        
        environment = { BORG_RSH = "ssh -i /etc/nixos/secrets/borg-fren-append.key"; };
        compression = "auto,zstd";
        doInit = true;
        startAt = "0/3:00:00"; # every 3 hrs
      };
    };
  };

  # NextCloud: ensure that postgres is running *before* running the setup
  systemd.services."nextcloud-setup" = {
    requires = [ "postgresql.service" ];
    after = [ "postgresql.service" ];
  };

  security.acme = {
    # Let's Encrypt Certificate Management
    defaults.email = fsimMail;
    acceptTerms = true;
  };

  virtualisation.oci-containers.containers = rec {
    passbolt = {
      image = "passbolt/passbolt";
      dependsOn = [ "passbolt-db" ];

      volumes = let 
        host-storage = "/var/lib/passbolt/passbolt";
      in [
        "${host-storage}/gpg:/etc/passbolt/gpg"
        "${host-storage}/jwt:/etc/passbolt/jwt"
      ];

      environment = {
        DATASOURCES_DEFAULT_PASSWORD = "passbolt";
        DATASOURCES_DEFAULT_HOST = "127.0.0.1";
        DATASOURCES_DEFAULT_USERNAME = "passbolt";
        DATASOURCES_DEFAULT_DATABASE = "passbolt";
        APP_FULL_BASE_URL = "https://${appSpecs.passbolt.domain}";

        EMAIL_TRANSPORT_DEFAULT_HOST = "smtp.hs-regensburg.de";
        EMAIL_TRANSPORT_DEFAULT_PORT = "25";
        EMAIL_TRANSPORT_DEFAULT_TLS = "false";
        EMAIL_DEFAULT_FROM = "fachschaft_im@oth-regensburg.de";
        EMAIL_TRANSPORT_DEFAULT_USERNAME = "fachschaft_im@oth-regensburg.de";

      };

      extraOptions = [
        "--network=container:passbolt-db"
      ];
    };

    passbolt-db = {
      image = "mariadb";

      ports = [
        "${builtins.toString appSpecs.passbolt.proxyPort}:80"
      ];

      volumes = [
        "/var/lib/passbolt/db:/var/lib/mysql"
      ];

      environment = {
        MARIADB_USER = "passbolt";
        MARIADB_PASSWORD = "passbolt";
        MARIADB_DATABASE = "passbolt";
        MARIADB_ROOT_PASSWORD = "root";
      };

    };
  
    chat = {
      image = "zulip/docker-zulip:8.4-0";
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
        "/var/log/zulip:/var/log/zulip"
        (toString ./services/zulip/zulip.conf + ":/etc/zulip/zulip.conf")
        (toString ./services/zulip/settings.py + ":/etc/zulip/settings.py")
        (toString ./secrets/zulip + ":/etc/zulip/zulip-secrets.conf")
      ];
      extraOptions = [ "--network=container:chat-db" ];
    };
    chat-db = {
      image = "zulip/zulip-postgresql:14";
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

    minecraft = {
      image = "itzg/minecraft-server:latest";
      environment = {
        MOTD = "FSIM Anarchie";
        VIEW_DISTANCE = "16";
        DIFFICULTY = "hard";

        SEED = "1785852800490497919";
        SPAWN_PROTECTION = "15";
        PLAYER_IDLE_TIMEOUT = "30";

        MEMORY = "16G";
        INIT_MEMORY = "8G";
        MAX_MEMORY = "64G";
        MAX_PLAYERS = "128";
        USE_AIKAR_FLAGS = "TRUE";

        RCON_PASSWORD = "8642753";

        TYPE = "PAPER";
        EULA = "TRUE";
        EXISTING_WHITELIST_FILE = "MERGE";
        USE_SIMD_FLAGS = "TRUE";
        UID = "25565";
        GID = "25565";
      };
      volumes = [
        "/var/lib/minecraft:/data:rw"
      ];
      ports = [ "25565:25565" ];
    };
  };

  # FSIM room tunnel
  networking.wireguard = {
    enable = true;
    interfaces."wg0" = {
      privateKeyFile = "/etc/nixos/secrets/wireguard-tunnel.key";
      listenPort = 4422;
      ips = [ "10.24.1.1/32" ];
      peers = [
        {
          allowedIPs = [ "10.24.1.2/32" "10.24.0.0/24" ];
          publicKey = "ElcCWQwmO1kyLYZOq30DkAwhy8F7Xh7A3jwJLTkUGHY=";
        }
        {
          allowedIPs = [ "10.24.1.101/32" ];
          publicKey = "Lw+fIYm7MQ9vZ21p3qKPsPe67occouBQb4VceQKjATQ=";
        }
      ];
    };
  };

  ###########################################################################
  # DANGER ZONE

  security = {
    sudo.enable = true; # popular and declining
    doas.enable = true; # simple and safe
  };
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
  };
  services.sshguard.enable = true;

  networking = {
    hostName = "ori";
    hosts = {
      "127.0.1.1" = [
        "im-srv-004"
        "im-srv-004.hs-regensburg.de"
      ];
      "10.24.1.2" = [
        "fren.fsim"
        "monolith.fsim"
      ];
    };

    # The global useDHCP flag is deprecated, therefore explicitly set to false here.
    useDHCP = false;
    interfaces.eno1.useDHCP = true;
    enableIPv6 = false; # none is provided

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
      device = "/dev/sda";
    };

    initrd.network.ssh = {
      enable = true;
      port = 22;
    };
    tmp.useTmpfs = true;

    kernel.sysctl = {
      # Allow containers to access internet
      "net.ipv4.ip_forward" = 1;
    };
  };

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    trusted-users = [ "@wheel" ];
  };

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "23.11"; # Did you read the comment?
}
