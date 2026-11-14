{
  description = "Linux Mobile Control Center (Mobile-RC) - zero-dependency Linux remote dashboard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      mkMobileRc = pkgs:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "mobile-rc";
          version = "1.0.0";
          src = self;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          dontBuild = true;

          installPhase = ''
            runHook preInstall

            install -Dm755 server.py "$out/libexec/mobile-rc/server.py"
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
            description = "Zero-dependency Python 3 mobile remote control web dashboard for Linux";
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
          pkg = mkMobileRc pkgs;
        in
        {
          mobile-rc = pkg;
          default = pkg;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/mobile-rc";
        };
      });

      nixosModules = {
        mobile-rc = import ./nix/module.nix self;
        default = self.nixosModules.mobile-rc;
      };
    };
}
