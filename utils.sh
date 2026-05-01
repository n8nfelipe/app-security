#!/usr/bin/env bash
# Detecta o gerenciador de pacotes do sistema e define a variável PKG_MANAGER.
# Uso: source utils.sh; então use $PKG_MANAGER para instalar/atualizar pacotes.

if grep -qi "fedora" /etc/os-release; then
  PKG_MANAGER="dnf"
else
  PKG_MANAGER="apt-get"
fi

export PKG_MANAGER
