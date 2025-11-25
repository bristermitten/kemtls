# Configuration for the project's Nix devShell
# You mostly want the `packages` option below.

{
  perSystem = { config, self', pkgs, ... }: {
    # Default shell.
    devShells.default = pkgs.mkShell {
      name = "kemtls";
      meta.description = "Haskell development environment";

      # See https://community.flake.parts/haskell-flake/devshell#composing-devshells
      inputsFrom = [
        config.haskellProjects.default.outputs.devShell # See ./nix/modules/haskell.nix
        config.pre-commit.devShell # See ./nix/modules/formatter.nix
      ];

      # Packages to be added to Nix devShell go here.
      packages = with pkgs; [
        just
        nixd
        ghciwatch
      ];

      buildInputs = [ pkgs.mctiny ];

      shellHook = ''
        export LD_LIBRARY_PATH=${pkgs.mctiny}/lib:$LD_LIBRARY_PATH
        export DYLD_LIBRARY_PATH=${pkgs.mctiny}/lib:$DYLD_LIBRARY_PATH
      '';
    };
  };
}
