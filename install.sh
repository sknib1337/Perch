#!/usr/bin/env bash
# Perch installer -- gets you from zero to hosting.
#
# It checks for Docker and Python, installs Perch, and tells you what to do
# next. It never installs anything without telling you first.
#
#   curl -fsSL https://raw.githubusercontent.com/sknib1337/Perch/main/install.sh | bash
#
# ...or just download this file, read it, and run:  bash install.sh

set -euo pipefail

# Where to install Perch from. Point this at your repo or PyPI package.
PERCH_SOURCE="${PERCH_SOURCE:-perch-host}"   # e.g. "perch-host" (PyPI) or "git+https://github.com/sknib1337/Perch"

say()  { printf "\n\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32mok\033[0m  %s\n" "$*"; }
warn() { printf "  \033[33m!!\033[0m  %s\n" "$*"; }

say "Perch installer"

# 1. Docker ----------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  ok "Docker is installed"
else
  warn "Docker isn't installed yet."
  case "$(uname -s)" in
    Linux)
      read -r -p "  Install Docker now with the official script? [y/N] " yn
      if [ "${yn:-N}" = "y" ] || [ "${yn:-N}" = "Y" ]; then
        curl -fsSL https://get.docker.com | sh
        ok "Docker installed"
      else
        echo "  Skipping. Install Docker yourself, then re-run this script."
        exit 1
      fi
      ;;
    Darwin|*)
      echo "  Please install Docker Desktop: https://www.docker.com/products/docker-desktop/"
      echo "  Open it once so it's running, then re-run this script."
      exit 1
      ;;
  esac
fi

# 2. Python 3.10+ ----------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
  ok "Python is installed"
else
  warn "Python 3 isn't installed."
  echo "  Install it from https://www.python.org/downloads/ and re-run this script."
  exit 1
fi

# 3. Install Perch (prefer pipx for a clean isolated install) -------------
say "Installing Perch"
if command -v pipx >/dev/null 2>&1; then
  pipx install "$PERCH_SOURCE" || pipx upgrade "$PERCH_SOURCE"
  ok "Installed with pipx"
else
  python3 -m pip install --user --upgrade "$PERCH_SOURCE"
  ok "Installed with pip (user)"
  warn "If the 'perch' command isn't found, add this to your shell profile:"
  echo '       export PATH="$HOME/.local/bin:$PATH"'
fi

say "Done. Next steps:"
cat <<'NEXT'
  1.  perch doctor      # confirm everything is ready
  2.  perch up          # create a sample app and bring it online
  3.  open http://web.localhost

  Then edit perch.yaml to add your own app or agent and run `perch up` again.
  Full walkthrough: see GETTING_STARTED.md
NEXT
