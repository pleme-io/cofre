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

      # ── The third binary: front 3's drop-in ─────────────────────────────────
      #
      # `suminuri-install-secrets` replaces sops-nix's `sops-install-secrets`
      # PROGRAM, not the sops CLI. That distinction is the whole reason it is a
      # separate member: sops-install-secrets links sops as a Go *library*, so no
      # PATH substitution can reach it — the only supported seam is sops-nix's
      # `sops.package`, and what belongs there is a program with the same argv
      # and manifest contract, which suminuri (a different argv contract
      # entirely) is not.
      #
      # Packaged here so `pleme.suminuri.installSecretsPackage` in the nix repo
      # has something to point at. That option has been declared-and-refused
      # since it was written, for the stated reason that "the drop-in binary does
      # not exist". It exists now.
      suminuri-install = substrate.rust.workspace {
        src = ./.;
        member = "suminuri-install";
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
              # Same treatment for both non-cofre members: drop the bare
              # `default`/`host-tool`/`unwrapped` so a consumer asking this flake
              # for `default` still means cofre. Silently changing that would be
              # the surprise.
              (removeAttrs (suminuri.${attr}.${system} or { }) [
                "default"
                "host-tool"
                "unwrapped"
              ])
              // (removeAttrs (suminuri-install.${attr}.${system} or { }) [
                "default"
                "host-tool"
                "unwrapped"
              ])
              // (cofre.${attr}.${system} or { });
          }) systems
        );

      # ── ★ THE DROP-IN NAME MUST BE IN THE STORE PATH ────────────────────
      #
      # `cargo build` produces both `suminuri-install-secrets` and
      # `sops-install-secrets` (two [[bin]] targets over one library entry
      # point). substrate's rust builder installs only the crate's single
      # derived tool name, so the second never reached $out/bin -- and
      # sops-nix resolves `${cfg.package}/bin/sops-install-secrets` literally.
      #
      # Measured on zek: pointing sops.package at the unwrapped package fails
      # at BUILD time with exit 127 ("command not found") while `cargo test`
      # and every behavioural differential pass, because they invoke the
      # binary by its own path and never resolve the caller's name.
      #
      # Wrapped here rather than in substrate: the need is specific to a
      # package that impersonates a foreign program, not a property every
      # fleet Rust tool wants. A symlink, so there is exactly one binary and
      # the two names cannot diverge.
      withDropInName =
        system: pkg:
        let
          pkgs = substrate.inputs.nixpkgs.legacyPackages.${system};
        in
        pkgs.runCommand "suminuri-install-secrets-dropin" { } ''
          mkdir -p $out/bin
          for b in ${pkg}/bin/*; do
            ln -s "$b" "$out/bin/$(basename "$b")"
          done
          ln -sf ${pkg}/bin/suminuri-install-secrets $out/bin/sops-install-secrets
          test -e $out/bin/sops-install-secrets || {
            echo "the drop-in name is missing from the wrapper" >&2; exit 1; }
        '';
    in
    cofre
    // {
      # ★ The wrapper is applied to EVERY variant, not just the host one: a
      # NixOS node consumes `suminuri-install-secrets-<target>` and would
      # otherwise get an unwrapped path with the drop-in name missing -- the
      # exact 127 this exists to prevent, reappearing on the arm that matters.
      packages = builtins.mapAttrs (
        system: ps:
        ps
        // builtins.listToAttrs (
          map
            (n: {
              name = n;
              value = withDropInName system ps.${n};
            })
            (builtins.filter (n: builtins.match "suminuri-install-secrets.*" n != null) (builtins.attrNames ps))
        )
      ) (mergeBySystem "packages");
      apps = mergeBySystem "apps";
    };
}
