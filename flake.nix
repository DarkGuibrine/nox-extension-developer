# SPDX-License-Identifier: AGPL-3.0-only
{
  description = "Project Nox · Extension Developer (Agent Skill & CLI)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      baseVersion =
        let
          changelogPath = ./CHANGELOG.md;
          lines =
            if builtins.pathExists changelogPath then
              lib.splitString "\n" (builtins.readFile changelogPath)
            else
              [ ];
          versionLine = lib.findFirst (
            line: builtins.match "^## [0-9]+\\.[0-9]+\\.[0-9]+.*" line != null
          ) null lines;
        in
        if versionLine != null then
          builtins.head (builtins.match "^## ([0-9]+\\.[0-9]+\\.[0-9]+).*" versionLine)
        else
          "0-unstable";

      revSuffix = self.shortRev or self.dirtyShortRev or "dirty";
      version = "${baseVersion}-${revSuffix}";

      skillSrc = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.difference ./. (
          lib.fileset.unions (
            map lib.fileset.maybeMissing [
              ./.git
              ./.github
              ./.gitignore
              ./flake.nix
              ./flake.lock
              ./tests
            ]
          )
        );
      };

      mkSkill =
        pkgs:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "nox-extension-developer-skill";
          inherit version;
          src = skillSrc;

          dontConfigure = true;
          dontBuild = true;
          dontPatchShebangs = true;

          installPhase = ''
            runHook preInstall
            mkdir -p "$out"
            cp -r ./. "$out/"
            runHook postInstall
          '';

          meta = {
            description = "Agent skill for Keiyoushi, Yuzono, and LNReader extension development";
            homepage = "https://github.com/ProjectNox-org/nox-extension-developer";
            license = lib.licenses.agpl3Only;
            platforms = lib.platforms.all;
          };
        };

      mkCli =
        pkgs: skill:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "nox-extension-developer";
          inherit version;

          dontUnpack = true;
          dontConfigure = true;
          dontBuild = true;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            runHook preInstall
            mkdir -p "$out/bin"
            makeWrapper "${pkgs.python3}/bin/python3" "$out/bin/nox" \
              --add-flags "${skill}/scripts/nox.py" \
              --set PYTHONDONTWRITEBYTECODE 1 \
              --suffix PATH : "${
                lib.makeBinPath (
                  [
                    pkgs.git
                    pkgs.nodejs
                  ]
                  ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.bubblewrap ]
                )
              }"
            runHook postInstall
          '';

          meta = {
            description = "CLI for Project Nox Extension Developer (Keiyoushi, Yuzono, and LNReader)";
            homepage = "https://github.com/ProjectNox-org/nox-extension-developer";
            license = lib.licenses.agpl3Only;
            mainProgram = "nox";
            platforms = lib.platforms.unix;
          };
        };

      homeManagerModule =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.programs.nox-extension-developer;
          inherit (pkgs.stdenv.hostPlatform) system;
        in
        {
          options.programs.nox-extension-developer = {
            enable = lib.mkEnableOption "Project Nox Extension Developer skill";

            skillPackage = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${system}.skill;
              defaultText = lib.literalExpression "inputs.nox-extension-developer.packages.\${pkgs.stdenv.hostPlatform.system}.skill";
              description = "Pacote contendo o diretório da skill (SKILL.md, references/ e scripts/).";
            };

            cliPackage = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${system}.cli;
              defaultText = lib.literalExpression "inputs.nox-extension-developer.packages.\${pkgs.stdenv.hostPlatform.system}.cli";
              description = "Pacote do comando CLI `nox`.";
            };

            installCli = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Instala o binário `nox` em `home.packages`.";
            };

            targets = {
              opencode = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = "Vincula a skill em `~/.config/opencode/skills/nox-extension-developer`.";
              };

              agents = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = "Vincula a skill em `~/.agents/skills/nox-extension-developer`.";
              };

              claude = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = "Vincula a skill em `~/.claude/skills/nox-extension-developer`.";
              };

              antigravity = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = "Vincula a skill em `~/.gemini/config/skills/nox-extension-developer`.";
              };

              extraPaths = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                example = [
                  ".local/share/agent-skills/nox-extension-developer"
                ];
                description = "Caminhos relativos a `$HOME` adicionais para vincular a skill.";
              };
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = lib.optional cfg.installCli cfg.cliPackage;

            xdg.configFile = lib.mkIf cfg.targets.opencode {
              "opencode/skills/nox-extension-developer".source = cfg.skillPackage;
            };

            home.file = lib.mkMerge [
              (lib.mkIf cfg.targets.agents {
                ".agents/skills/nox-extension-developer".source = cfg.skillPackage;
              })
              (lib.mkIf cfg.targets.claude {
                ".claude/skills/nox-extension-developer".source = cfg.skillPackage;
              })
              (lib.mkIf cfg.targets.antigravity {
                ".gemini/config/skills/nox-extension-developer".source = cfg.skillPackage;
              })
              (lib.genAttrs cfg.targets.extraPaths (_: {
                source = cfg.skillPackage;
              }))
            ];
          };
        };

      hmModules = {
        nox-extension-developer = homeManagerModule;
        default = homeManagerModule;
      };
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          skill = mkSkill pkgs;
          cli = mkCli pkgs skill;
        in
        {
          inherit skill cli;
          default = skill;
        }
      );

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.cli;
        };
      });

      checks = forAllSystems (pkgs: {
        upstream-suite = pkgs.stdenvNoCC.mkDerivation {
          pname = "nox-extension-developer-checks";
          inherit version;
          src = self;

          nativeBuildInputs = [
            pkgs.python3
            pkgs.git
            pkgs.nodejs
          ];

          postPatch = ''
            # Compatibilidade com a sandbox de build do Nix (sem /usr/bin/python3 e com raiz em /build).
            substituteInPlace tests/test_references.py \
              --replace-quiet "/usr/bin/python3" "${pkgs.python3}/bin/python3"
            substituteInPlace scripts/nox_android.py \
              --replace-quiet "for part in gf.parts" "for part in gf.relative_to(root).parts" \
              --replace-quiet "for part in sf.parts" "for part in sf.relative_to(root).parts"
          '';

          dontConfigure = true;
          dontBuild = true;
          doCheck = true;

          checkPhase = ''
            runHook preCheck
            export HOME="$TMPDIR/home"
            export XDG_CACHE_HOME="$TMPDIR/cache"
            export PYTHONDONTWRITEBYTECODE=1
            mkdir -p "$HOME" "$XDG_CACHE_HOME"

            python3 -c "import ast, pathlib; [ast.parse(p.read_bytes(), filename=str(p)) for d in ('scripts', 'tests') for p in pathlib.Path(d).glob('*.py')]"
            python3 -m unittest discover -s tests -v
            python3 scripts/nox.py matrix --validate
            python3 scripts/nox.py scenarios
            python3 scripts/nox.py benchmark
            python3 scripts/nox.py security-audit .
            python3 scripts/nox.py verify-report README.md
            python3 scripts/nox.py verify-report README.en.md
            python3 scripts/package.py "$TMPDIR/nox-ci-candidate.zip"
            rm -f "$TMPDIR/nox-ci-candidate.zip"
            runHook postCheck
          '';

          installPhase = ''
            runHook preInstall
            touch "$out"
            runHook postInstall
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShellNoCC {
          packages = [
            pkgs.python3
            pkgs.git
            pkgs.nodejs
          ]
          ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.bubblewrap ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);

      overlays.default = final: _prev: {
        nox-extension-developer-skill = self.packages.${final.stdenv.hostPlatform.system}.skill;
        nox-extension-developer = self.packages.${final.stdenv.hostPlatform.system}.cli;
      };

      homeModules = hmModules;
      homeManagerModules = hmModules;
    };
}
