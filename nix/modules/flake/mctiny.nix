{ lib, ... }: {
  perSystem = { config, pkgs, ... }: {
    packages.mctiny = pkgs.stdenv.mkDerivation {
      name = "mctiny";
      src = ../../../mctiny;
      nativeBuildInputs = [ pkgs.python3 ];

      # 1. OPTIONAL: Speed up compilation
      enableParallelBuilding = true;

      # 2. OPTIONAL: Explicit build flags if needed (uncomment to use)
      makeFlags = [ "libmctiny.${if pkgs.stdenv.hostPlatform.isDarwin then "dylib" else "so"}" ];

      # 3. FIXED Install Phase
      installPhase = ''
        mkdir -p $out/lib $out/include $out/bin
        
        # Nix calculates the extension at evaluation time, so the shell script is simpler
        cp libmctiny.${if pkgs.stdenv.hostPlatform.isDarwin then "dylib" else "so"} $out/lib/
        
        cp mctiny.h $out/include/
        cp crypto_kem_mceliece6960119.h $out/include/

           cp mctiny-test $out/bin/
      '';
      meta.mainProgram = "mctiny-test";
    };


  };
}
