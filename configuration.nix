# This is an example of a 'configuration.nix' file to spawn
# a development environment with a postgres 9.0 database and 
# python 2.7 installed.
{ config, pkgs, ...}:
{
  services.postgresql = {
    enable = true;
    package = pkgs.postgresql90;
  };

  environment.systemPackages = with pkgs; [
    python27
  ];
}
