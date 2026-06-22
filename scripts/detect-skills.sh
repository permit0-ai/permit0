#!/usr/bin/env bash
# Detect the tech stack of a project and emit matching skill names (one per line, sorted).
# Reads files in REPO_ROOT (default: repo containing this script).
# Skills sourced from: https://github.com/affaan-m/everything-claude-code
set -uo pipefail
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
R="$REPO_ROOT"

_emit() { printf '%s\n' "$@"; }

_has_file() {  # true if any of the named files exist directly under REPO_ROOT
  local f; for f in "$@"; do [[ -f "$R/$f" ]] && return 0; done; return 1
}

_find_ext() {  # true if any files with the given extension exist (up to depth 4, no hidden/node_modules)
  find "$R" -maxdepth 4 -name "*.$1" \
    -not -path "*/\.*" -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null \
    | grep -q .
}

# --- C++ ---
if _find_ext cpp || _find_ext cc || _find_ext cxx || _has_file CMakeLists.txt; then
  _emit cpp-coding-standards cpp-testing
fi

# --- Python ---
if _has_file requirements.txt pyproject.toml setup.py Pipfile; then
  _emit python-patterns python-testing
  # Django
  if _has_file manage.py || grep -ql "django" "$R/requirements.txt" "$R/pyproject.toml" 2>/dev/null; then
    _emit django-patterns django-tdd
  fi
fi

# --- Go ---
if _has_file go.mod; then
  _emit golang-patterns golang-testing
fi

# --- Rust ---
if _has_file Cargo.toml; then
  _emit rust-patterns rust-testing
fi

# --- TypeScript / JavaScript ---
if _has_file tsconfig.json tsconfig.base.json \
    || ( _has_file package.json && grep -q '"typescript"' "$R/package.json" 2>/dev/null ); then
  _emit frontend-patterns
  # Next.js
  if _has_file next.config.js next.config.ts next.config.mjs; then
    _emit nextjs-turbopack
  fi
fi

# --- Java / Spring Boot ---
if _has_file pom.xml \
    || find "$R" -maxdepth 3 -name "build.gradle" -not -path "*/\.*" 2>/dev/null | grep -q .; then
  _emit java-coding-standards
  if grep -ql "spring" "$R/pom.xml" 2>/dev/null \
      || find "$R" -maxdepth 3 -name "build.gradle" -not -path "*/\.*" 2>/dev/null \
           | xargs grep -ql "spring" 2>/dev/null; then
    _emit springboot-patterns springboot-tdd
  fi
fi

# --- Kotlin ---
if _find_ext kt || _find_ext kts; then
  _emit kotlin-patterns kotlin-testing
  # Android
  if find "$R" -maxdepth 5 -name "AndroidManifest.xml" 2>/dev/null | grep -q .; then
    _emit android-clean-architecture
  fi
fi

# --- Swift ---
if _find_ext swift; then
  _emit swift-concurrency-6-2 swiftui-patterns
fi

# --- Laravel (PHP) ---
if _has_file artisan \
    || ( _has_file composer.json && grep -q '"laravel' "$R/composer.json" 2>/dev/null ); then
  _emit laravel-patterns laravel-tdd
fi

# --- Perl ---
if _find_ext pl || _find_ext pm; then
  _emit perl-patterns perl-testing
fi

# --- Docker / backend ---
if _has_file Dockerfile docker-compose.yml docker-compose.yaml; then
  _emit docker-patterns backend-patterns
  # PostgreSQL in compose
  if grep -ql "postgres" "$R/docker-compose.yml" "$R/docker-compose.yaml" 2>/dev/null; then
    _emit postgres-patterns
  fi
fi

# --- Security (always added when any stack was detected) ---
_emit security-review
