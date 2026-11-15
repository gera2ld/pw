default:
    just --list

build:
    go run build.go

[positional-arguments]
run *args:
    go run ./cmd/pw "$@"
