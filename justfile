VERSION := "0.6.0"
APP := "showcert"
DOCKER_IMAGE := "andreburgaud" / APP
BUILD_DIR := "build"
DEBUG_DIR := BUILD_DIR / "debug"
RELEASE_DIR := BUILD_DIR / "release"

alias b := build
alias c := clean
alias t := test
alias v := version
alias ghp := github-push
alias dc := docker-clean
alias dp := docker-push
alias r := release

# Default recipe (this list)
default:
    @just --list

# Clean binaries
clean:
    -rm -rf {{BUILD_DIR}}
    -rm -rf tmp

# Create certs for testing
create_certs:
    ./create_certs.sh

# Execute tests
test:
    go test -v ./...

# Build showcert debug version
build:
    go build -o {{DEBUG_DIR}}/{{APP}} showcert/cmd/showcert

# Build sowcert release version
release:
    go build -o {{RELEASE_DIR}}/{{APP}} -ldflags="-s -w -X 'showcert/internal/cli.Version={{VERSION}}'" showcert/cmd/showcert
    -upx {{RELEASE_DIR}}/{{APP}}

# Quick run test of a release build (help and google.com)
run: release
    {{RELEASE_DIR}}/{{APP}}
    {{RELEASE_DIR}}/{{APP}} google.com

# Build a local docker image
docker:
    docker build -t {{DOCKER_IMAGE}} .
    docker build --build-arg SHOWCERT_VERSION={{VERSION}} -t {{DOCKER_IMAGE}}:{{VERSION}} .

# Push showcert docker image to docker hub
docker-push: docker
    docker push docker.io/{{DOCKER_IMAGE}}:{{VERSION}}
    docker tag {{DOCKER_IMAGE}}:{{VERSION}} docker.io/{{DOCKER_IMAGE}}:latest
    docker push docker.io/{{DOCKER_IMAGE}}:latest

# Clean local images
docker-clean:
    docker rmi -f $(docker images | grep showcert | tr -s ' '| cut -d ' ' -f 3)
    docker rmi $(docker images -f dangling=true -q)

# Format Go code
fmt:
    gofmt -w .

# Push and tag the code to Github
github-push: version
    @git push
    @git tag -a {{VERSION}} -m "Version {{VERSION}}"
    @git push origin --tags

# Display the version
version:
    @echo "version {{VERSION}}"
