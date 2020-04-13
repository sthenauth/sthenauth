{ pkgs ? import <nixpkgs> {}
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
    $server->start;
    $server->waitForUnit("sthenauth.service");
    $server->waitUntilSucceeds('netstat -lWn46 | awk \'{print $4}\' | grep --fixed-strings :3001');
    $server->copyFileFromHost("${./test.sh}", "/tmp/test.sh");
    print($server->succeed("${pkgs.bash}/bin/bash /tmp/test.sh"));
  '';
}
