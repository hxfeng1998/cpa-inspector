PLUGIN := cpa-inspector
OUT    := dist/$(PLUGIN).so
GOFLAGS_BUILD := -buildmode=c-shared -trimpath -ldflags="-s -w"

.PHONY: build docker-build test clean

# 本机构建（需要 Go 1.26+ 与 gcc）。产物文件名即插件 ID，不要改名。
build:
	CGO_ENABLED=1 go build $(GOFLAGS_BUILD) -o $(OUT) .
	@rm -f dist/$(PLUGIN).h
	@echo "built $(OUT)"

# 用与官方镜像相同的 golang:1.26-bookworm 构建，保证 glibc 与 Docker 部署的 CLIProxyAPI 兼容。
# 交叉架构：make docker-build PLATFORM=linux/arm64
PLATFORM ?= linux/amd64
docker-build:
	docker run --rm --platform $(PLATFORM) -v "$(CURDIR)":/src -w /src golang:1.26-bookworm \
		sh -c 'CGO_ENABLED=1 go build $(GOFLAGS_BUILD) -buildvcs=false -o $(OUT) . && rm -f dist/$(PLUGIN).h'

test:
	go vet ./... && go test -race -count=1 ./...

clean:
	rm -rf dist
