#!/bin/sh
set -e
rm -rf completions
mkdir completions
for sh in bash zsh fish; do
	go run cmd/sifre/main.go completion "$sh" >"completions/sifre.$sh"
done
