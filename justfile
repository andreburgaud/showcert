VERSION := "0.3.0"
APP := "showcert"
BUILD_DIR := "build"
DEBUG_DIR := BUILD_DIR / "debug"
RELEASE_DIR := BUILD_DIR / "release"

alias b := build
alias c := clean
alias t := test
alias v := version
alias pt := push-tag
alias r := release

# Default recipe (this list)
default:
    @just --list

# Clean binaries
clean:
	-rm -rf {{BUILD_DIR}}

# Execute tests
test:
	@echo Not implemented yet

build:
	go build -o {{DEBUG_DIR}}/{{APP}} showcert/cmd/showcert

release:
    go build -o {{RELEASE_DIR}}/{{APP}} -ldflags="-s -w -X 'showcert/internal/cli.Version={{VERSION}}'" showcert/cmd/showcert
    -upx {{RELEASE_DIR}}/{{APP}}

# Tag and push the code to Github
push-tag: version
    @git push
    @git tag -a {{VERSION}} -m "Version {{VERSION}}"
    @git push origin --tags

# Display the version
version:
    @echo "version {{VERSION}}"
