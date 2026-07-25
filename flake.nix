{
  description = "A modern reimplementation of YARA in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # Pin x86_64-darwin to a stable release branch for older macOS Intel
    # compatibility. See references/flake-templates/darwin-legacy-pin.md.
    nixpkgs-darwin-legacy.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { self, nixpkgs, nixpkgs-darwin-legacy }: let
    version = "1.19.0";

    assets = {
      "x86_64-linux" = {
        file = "yara-x-v1.19.0-x86_64-unknown-linux-gnu.tar.gz";
        sha256 = "a97d78189e3548797ac45b7b4a5fd8975783861875c594f772ec9b8bb5fa4d72";
      };
      "aarch64-linux" = {
        file = "yara-x-v1.19.0-aarch64-unknown-linux-gnu.tar.gz";
        sha256 = "20443fc16081c68f7a2ca070feb84ae33a89c7dc726851bf050690e55937db77";
      };
      "x86_64-darwin" = {
        file = "yara-x-v1.19.0-x86_64-apple-darwin.tar.gz";
        sha256 = "2c9b9778890d2e2bb10faf0ce21087e6cf012793ba90bb611cdc0b06e18b44e8";
      };
      "aarch64-darwin" = {
        file = "yara-x-v1.19.0-aarch64-apple-darwin.tar.gz";
        sha256 = "b6e62d6388412a86655340513ccfd7ac9ea5e98868e870dd4a4c029909ebf87b";
      };
    };

    systems = builtins.attrNames assets;
    forAllSystems = nixpkgs.lib.genAttrs systems;

    # Prebuilt binary from release tarball
    yara-xFor = system: let
      pkgs =
        if system == "x86_64-darwin"
        then nixpkgs-darwin-legacy.legacyPackages.${system}
        else nixpkgs.legacyPackages.${system};
      asset = assets.${system};
    in pkgs.stdenv.mkDerivation {
      pname = "yara-x";
      inherit version;

      src = pkgs.fetchurl {
        url = "https://github.com/VirusTotal/yara-x/releases/download/v${version}/${asset.file}";
        inherit (asset) sha256;
      };

      sourceRoot = ".";

      nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];
      buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ];

      dontConfigure = true;
      dontBuild = true;

      installPhase = ''
        runHook preInstall
        mkdir -p "$out/bin"
        cp yr "$out/bin/yr"
        chmod +x "$out/bin/yr"
        runHook postInstall
      '';

      meta = with pkgs.lib; {
        description = "A modern reimplementation of YARA in Rust";
        homepage = "https://github.com/VirusTotal/yara-x";
        downloadPage = "https://github.com/VirusTotal/yara-x/releases";
        license = licenses.bsd3;
        mainProgram = "yr";
        platforms = systems;
        sourceProvenance = [ sourceTypes.binaryNativeCode ];
      };
    };

    # From-source build — builds only the `yr` CLI binary from the Cargo
    # workspace. The capi, py, and js-wasm crates have special build
    # requirements (cargo-c, pyo3, wasm-bindgen) that are not needed for
    # the CLI and would complicate the build unnecessarily.
    sourceFor = system: let
      pkgs =
        if system == "x86_64-darwin"
        then nixpkgs-darwin-legacy.legacyPackages.${system}
        else nixpkgs.legacyPackages.${system};
    in pkgs.rustPlatform.buildRustPackage {
      pname = "yara-x";
      inherit version;
      # cleanSource filters build artifacts, .git, .devbox, etc., so
      # trivial local changes do not invalidate the Nix build cache.
      src = pkgs.lib.cleanSource ./.;
      cargoLock.lockFile = ./Cargo.lock;
      # Only build the `yr` CLI binary, not the entire workspace (capi,
      # py, js-wasm have special build requirements).
      cargoBuildFlags = [ "--bin" "yr" ];
      # CLI tests require the binary to exist first and special env setup;
      # library tests are extensive and slow. Skip in the Nix build.
      doCheck = false;
      meta = {
        description = "A modern reimplementation of YARA in Rust";
        homepage = "https://github.com/VirusTotal/yara-x";
        license = pkgs.lib.licenses.bsd3;
        mainProgram = "yr";
      };
    };
  in {
    packages = forAllSystems (system: rec {
      yara-x = yara-xFor system;
      prebuilt = yara-x;
      default = prebuilt;
      source = sourceFor system;
    });

    apps = forAllSystems (system: let
      # WARNING: do NOT replace this `let` binding with `rec` referencing the
      # `packages` attrset above. A `rec { default = { program = "${yara-x}/bin/..."; }; }`
      # that names the binding `yara-x` shadows the `let`-bound derivation, so
      # `${yara-x}` interpolates the app attrset (a set, not a store path) and
      # throws "cannot coerce a set to a string" at `nix run` / `nix flake check`.
      # The separate `let yara-xPkg = yara-xFor system;` binding keeps the
      # derivation in scope as a store path.
      yara-xPkg = yara-xFor system;
      sourcePkg = sourceFor system;
    in {
      yara-x = {
        type = "app";
        program = "${yara-xPkg}/bin/yr";
      };
      prebuilt = {
        type = "app";
        program = "${yara-xPkg}/bin/yr";
      };
      default = {
        type = "app";
        program = "${yara-xPkg}/bin/yr";
      };
      source = {
        type = "app";
        program = "${sourcePkg}/bin/yr";
      };
    });

    checks = forAllSystems (system: {
      # CI exercises both the prebuilt and source outputs
      prebuilt = yara-xFor system;
      source = sourceFor system;
    });
  };
}
