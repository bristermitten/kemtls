# haskell-flake configuration goes in this module.

{ root, inputs, ... }:
{
  imports = [
    inputs.haskell-flake.flakeModule
  ];
  perSystem = { self', lib, config, pkgs, ... }: {
    haskellProjects.default = {
      projectRoot = builtins.toString (lib.fileset.toSource {
        inherit root;
        fileset = lib.fileset.unions [
          (root + /src)
          (root + /kemtls.cabal)
        ];
      });

      # The base package set (this value is the default)
      basePackages = pkgs.haskell.packages.ghc912;

      # Add your package overrides here
      settings = {
        kemtls = {
          stan = true;
          librarySystemDepends = [ pkgs.mctiny ];
          extraLibraries = [ pkgs.mctiny ];
        };
      };

      autoWire = [ "packages" "apps" "checks" ];
    };

    packages.default = self'.packages.kemtls;
    apps.default = self'.apps.kemtls;
  };
}
