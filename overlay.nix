# An overlay to make it easier to merge all essential-wallet related packages
# into nixpkgs.
{}: final: prev: {
  essential-wallet = prev.callPackage ./essential-wallet.nix { };
  essential-wallet-test = final.essential-wallet.overrideAttrs (finalAttr: prevAttr: {
    cargoBuildFeatures = [ "test-utils" ];
    postInstall = ''
      mv $out/bin/essential-wallet $out/bin/essential-wallet-test
    '';
  });
}
