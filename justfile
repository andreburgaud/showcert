VERSION := "0.4.0"
APP := "showcert"
DOCKER_IMAGE := "andreburgaud" / APP
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
    go test -v ./...

# Build showcert debug version
build:
    go build -o {{DEBUG_DIR}}/{{APP}} showcert/cmd/showcert

# Build sowcert release version
release:
    go build -o {{RELEASE_DIR}}/{{APP}} -ldflags="-s -w -X 'showcert/internal/cli.Version={{VERSION}}'" showcert/cmd/showcert
    -upx {{RELEASE_DIR}}/{{APP}}

# Build a local docker image
docker:
    sudo docker build -t showcert .
    sudo docker build --build-arg SHOWCERT_VERSION={{VERSION}} -t {{DOCKER_IMAGE}}:{{VERSION}} .

# Push showcert docker image to docker hub
docker-push: docker
    sudo docker push docker.io/{{DOCKER_IMAGE}}:{{VERSION}}
    sudo docker tag {{DOCKER_IMAGE}}:{{VERSION}} docker.io/{{DOCKER_IMAGE}}:latest
    sudo docker push docker.io/{{DOCKER_IMAGE}}:latest

# Format Go code
fmt:
    gofmt -w .

# Tag and push the code to Github
push-tag: version
    @git push
    @git tag -a {{VERSION}} -m "Version {{VERSION}}"
    @git push origin --tags

# Display the version
version:
    @echo "version {{VERSION}}"
