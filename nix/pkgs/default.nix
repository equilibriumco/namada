{
  perSystem = {
    pkgs,
    env,
    meta,
    ...
  }: {
    packages.default = pkgs.rustPlatform.buildRustPackage {
      inherit env;
      inherit (meta) src buildInputs;
      inherit (meta.cargoManifest.workspace.package) version;

      pname = "namada";

      cargoLock = {
        inherit (meta) lockFile;
        outputHashes = {
          "halo2_gadgets-0.3.1" = "sha256-+1tMFB2w70mJPAiYJboO5rtu0C+rUuPi9qvHf7kk04U=";
          "orchard-0.11.0" = "sha256-jVoOLFAQy1BtaOccQbb+dhrlcX0Jyqy65twuo0d0QlM=";
          "sapling-crypto-0.5.0" = "sha256-UwxRBXEhvlcar4g3mKAirke3/oyFBI9+DHPVpLeb2bQ=";
          "zair-core-0.1.0" = "sha256-68UcHWft8FFr1OQkq+K0gvhPvNcigs4APOjzVz7rlQI=";
        };
      };

      nativeBuildInputs = meta.nativeBuildInputs ++ [meta.rustToolchain];

      # Disable the check phase to speed up build times.
      doCheck = false;
    };
  };
}
