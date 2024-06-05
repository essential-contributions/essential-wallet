# An overlay to make it easier to merge all essential-wallet related packages
# into nixpkgs.
{}: final: prev: {
  essential-wallet = prev.callPackage ./essential-wallet.nix { };
}
