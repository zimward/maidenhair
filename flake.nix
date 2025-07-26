{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    inputs:
    with inputs;
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        shellInputs = with pkgs; [
          pkg-config
          openssl
          sqlite
          rustPlatform.bindgenHook
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs =
            shellInputs
            ++ (with pkgs; [
              cargo
              rustc
              rust-analyzer
              rustfmt
              clippy
            ]);
        };
      }
    );
}
