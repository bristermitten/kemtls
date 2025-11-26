{ lib, inputs, ... }: {
  perSystem = { config, pkgs, system, ... }: {
    _module.args.pkgs = import inputs.nixpkgs {
      inherit system;
      overlays = [
        (final: prev: {
          mctiny = final.stdenv.mkDerivation {
            name = "mctiny";
            src = ../../../mctiny;
            nativeBuildInputs = [ pkgs.python3 ];

            enableParallelBuilding = true;

            makeFlags = [ "libmctiny.${if final.stdenv.hostPlatform.isDarwin then "dylib" else "so"}" "mctiny-test" ];

            installPhase = ''
              mkdir -p $out/lib $out/include $out/bin
        
              cp libmctiny.${if final.stdenv.hostPlatform.isDarwin then "dylib" else "so"} $out/lib/
        
              cp mctiny.h $out/include/
              cp crypto_kem_mceliece6960119.h $out/include/
              cp mctiny-test $out/bin/
            '';
            meta.mainProgram = "mctiny-test";
          };
        })
      ];
    };



  };
}
