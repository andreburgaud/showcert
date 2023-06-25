VERSION := "0.9.2"
APP := "showcert"
DOCKER_IMAGE := "andreburgaud" / APP
BUILD_DIR := "build"
DEBUG_DIR := BUILD_DIR / "debug"

alias c := clean
alias t := test
alias v := version
alias ghp := github-push
alias dc := docker-clean
alias dp := docker-push
alias cr := check-release
alias db := dev-build
alias rel := release
alias lrel := local-release


# Default recipe (this list)
default:
    @just --list

# Clean binaries
clean:
    -rm -rf tmp
    -rm -rf dist

# Create certs for testing
create_certs:
    ./create_certs.sh

# Execute tests
test:
    go test -v ./...

# Build showcert debug version (needed for GitHub Actions)
build:
    go build -o {{DEBUG_DIR}}/{{APP}} {{APP}}/cmd/{{APP}}

# Check release configuration
check-release:
    goreleaser check

# Build a release and publish to GitHub
release:
    goreleaser release --clean

# Build a local snapshot release
local-release:
    goreleaser release --clean --snapshot

# Local development build
dev-build:
    goreleaser build --clean --single-target --snapshot

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
    docker rmi -f $(docker images | grep {{APP}} | tr -s ' '| cut -d ' ' -f 3)
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
