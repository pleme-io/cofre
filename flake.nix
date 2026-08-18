{
  description = "cofre — typed secret materialization. Generate + seed secrets without ever seeing plaintext. Also ships suminuri (墨塗り), the sops-wire-compatible encrypted-file tool.";

  # substrate.rust.workspace dispatches over Cargo.gen.lock (the slim gen delta,
  # reconstructed to the full BuildSpec in pure Nix) — no crate2nix, no Cargo.nix.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs =
    { substrate, ... }:
    let
      # ── Two binaries, two calls ─────────────────────────────────────────────
      #
      # `substrate.rust.workspace` builds exactly ONE member: `mk-rust-tool-flake`
      # picks a single crate and derives the tool name, repo slug and release
      # wiring from that crate's `[package.metadata.pleme]`. There is no
      # `members = [ … ]` form, and inventing one here would be a fork of the
      # shared builder rather than a use of it.
      #
      # So it is called once per binary and the outputs are merged. The merge is
      # deliberately ASYMMETRIC: cofre's outputs win every collision, so
      # `packages.default`, every `apps.*` (release / bump / confirm / sbom …)
      # and `checks` stay exactly what they were. Nothing that already consumed
      # this flake sees a change; `suminuri` is additive.
      #
      # The alternative — a second flake in a subdirectory — would split one
      # workspace's Cargo.lock across two build specs, which is precisely the
      # gen delta-tie that the pre-commit hook exists to catch.
      cofre = substrate.rust.workspace {
        src = ./.;
        member = "cofre";
      };

      suminuri = substrate.rust.workspace {
        src = ./.;
        member = "suminuri";
      };

      # Per-system merge, cofre last so it wins.
      mergeBySystem =
        attr:
        let
          systems = builtins.attrNames (suminuri.${attr} or { });
        in
        builtins.listToAttrs (
          map (system: {
            name = system;
            value =
              # `suminuri`'s own package set is prefixed so its per-target
              # variants (`suminuri-aarch64-apple-darwin`, …) do not collide with
              # cofre's, and its bare `default`/`host-tool`/`unwrapped` are
              # dropped — a consumer asking this flake for `default` means cofre,
              # and silently changing that would be the surprise.
              (removeAttrs (suminuri.${attr}.${system} or { }) [
                "default"
                "host-tool"
                "unwrapped"
              ])
              // (cofre.${attr}.${system} or { });
          }) systems
        );
    in
    cofre
    // {
      packages = mergeBySystem "packages";
      apps = mergeBySystem "apps";
    };
}
