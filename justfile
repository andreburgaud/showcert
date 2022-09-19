VERSION := "0.1.0"
APP := "showcert"

alias b := build
alias c := clean
alias t := test
alias v := version
alias pt := push-tag
alias rel := release

# Default recipe (this list)
default:
    @just --list

# Clean binaries
clean:
	-rm {{APP}}

# Execute tests
test:
	@echo Not implemented yet

build:
	go build -o {{APP}} *.go
release:
    go build -ldflags="-s -w" -o {{APP}} *.go
    upx {{APP}}

# Tag and push the code to Github
push-tag: version
    @git push
    @git tag -a {{VERSION}} -m "Version {{VERSION}}"
    @git push origin --tags

# Display the version
version:
    @echo "version {{VERSION}}"
