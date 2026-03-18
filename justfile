set positional-arguments

default:
  just --list

build:
  go run build.go

run *args:
  go run ./cmd/pw "$@"
