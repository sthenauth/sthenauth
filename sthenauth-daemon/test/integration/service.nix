{ config, pkgs, lib, ...}:

with lib;

let
  cfg = config.services.test.sthenauth;
in
{
  options.services.test.sthenauth = {
    package = mkOption {
      type = types.package;
      default = (import ../.. { inherit pkgs; }).bin;
    };
  };

  config = {
    services.postgresql = {
      enable = true;
      package = pkgs.postgresql;
      ensureDatabases = [ "sthenauth" ];

      ensureUsers = singleton {
        name = "root";
        ensurePermissions = {
          "ALL TABLES IN SCHEMA public" = "ALL PRIVILEGES";
        };
      };

      authentication = mkForce ''
        local all all trust
      '';
      # extraConfig = ''
      #   log_statement = all
      # '';
    };

    systemd.services.sthenauth = {
      description = "Test service for Sthenauth";
      path = [ cfg.package pkgs.postgresql ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "postgresql.service" ];
      environment = {
        STHENAUTH_DB = "dbname=sthenauth";
        STHENAUTH_SECRETS_DIR = "/tmp/sthenauth";
      };

      preStart = ''
        mkdir -p /var/lib/sthenauth

        # FIXME: Document this:
        echo 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' | \
          ${pkgs.sudo}/bin/sudo -u postgres psql -tA sthenauth
      '';

      script = "sthenauth --init --migrate server --port=3001 --test-mode";
    };
  };
}
