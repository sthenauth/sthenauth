{ pkgs ? import ../../../nix/nixpkgs.nix {}
}:

pkgs.nixosTest {
  name = "sthenauth-integration-tests";

  nodes = {
    server = {config, pkgs, ...}: {
      imports = [ ./service.nix ];
      environment.systemPackages = [
        pkgs.openssl
        config.services.test.sthenauth.package
      ];
    };
  };

  testScript = ''
    server.start()
    server.wait_for_unit("sthenauth.service")
    server.wait_for_open_port(3001)
    server.copy_from_host(
        "${./test.sh}", "/tmp/test.sh"
    )
    server.succeed(
        "${pkgs.bash}/bin/bash /tmp/test.sh"
    )
  '';
}
