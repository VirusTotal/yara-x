{
  description = "A devShell with a rust toolchain for cross-compiling to windows";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          crossSystem = {
            config = "x86_64-w64-mingw32";
          };
          overlays = [
            (import rust-overlay)
          ];
        };

        # I don't understand why we need this instead of just using pkgs.pkgsBuildHost,
        # but the wine64 from here works and the wine64 from pkgs.pkgsBuildHost doesn't.
        pkgsLocal = import nixpkgs {
          inherit system;
        };
        rust-toolchain = pkgs.pkgsBuildHost.rust-bin.stable.latest.default.override {
            targets = [ "x86_64-pc-windows-gnu" ];
          };
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = lib.optionals hostPlatform.isWindows [
            pkgs.windows.mingw_w64_pthreads
          ];
          nativeBuildInputs = [
            rust-toolchain
            pkgsLocal.wine64
          ];
        };
      }
    );
}
