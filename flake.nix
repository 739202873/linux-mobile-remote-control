{
  description = "Mobile-RC - Universal Cross-Platform Remote Control Center (Rust + Python 3 Fallback)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      mkMobileRcPython = pkgs:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "mobile-rc-python";
          version = "3.0.0";
          src = self;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          dontBuild = true;

          installPhase = ''
            runHook preInstall

            install -Dm755 fallback/server.py "$out/libexec/mobile-rc/server.py"
            install -Dm755 bin/control-access "$out/libexec/mobile-rc/control-access.py"
            install -Dm644 termux/control-access "$out/share/mobile-rc/termux-control-access.sh"

            mkdir -p "$out/bin"
            makeWrapper "${pkgs.python3}/bin/python3" "$out/bin/mobile-rc" \
              --add-flags "$out/libexec/mobile-rc/server.py"
            makeWrapper "${pkgs.python3}/bin/python3" "$out/bin/control-access" \
              --add-flags "$out/libexec/mobile-rc/control-access.py"

            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Zero-dependency Python 3 fallback runtime for Mobile-RC";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "mobile-rc";
          };
        };

      mkMobileRcRust = pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "mobile-rc";
          version = "3.0.0";
          src = self;

          cargoRoot = "daemon-rs";
          cargoLock.lockFile = ./daemon-rs/Cargo.lock;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          postInstall = ''
            install -Dm755 "${self}/bin/control-access" "$out/libexec/mobile-rc/control-access.py"
            install -Dm644 "${self}/termux/control-access" "$out/share/mobile-rc/termux-control-access.sh"
            makeWrapper "${pkgs.python3}/bin/python3" "$out/bin/control-access" \
              --add-flags "$out/libexec/mobile-rc/control-access.py"
          '';

          meta = with pkgs.lib; {
            description = "Native Rust remote control web dashboard daemon for Linux";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "mobile-rc";
          };
        };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          rustPkg = mkMobileRcRust pkgs;
          pyPkg = mkMobileRcPython pkgs;
        in
        {
          mobile-rc = rustPkg;
          mobile-rc-rust = rustPkg;
          mobile-rc-python = pyPkg;
          default = rustPkg;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/mobile-rc";
        };
        python = {
          type = "app";
          program = "${self.packages.${system}.mobile-rc-python}/bin/mobile-rc";
        };
      });

      nixosModules = {
        mobile-rc = import ./nix/module.nix self;
        default = self.nixosModules.mobile-rc;
      };
    };
}
