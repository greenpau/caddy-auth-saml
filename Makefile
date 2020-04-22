.PHONY: test ctest covdir coverage docs linter qtest clean dep misc release
PLUGIN_NAME="caddy-auth-saml"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
VERBOSE:=-v
ifdef TEST
	TEST:="-run ${TEST}"
endif

all:
	@echo "Version: $(PLUGIN_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"
	@rm -rf ./bin/caddy
	@rm -rf ../xcaddy-$(PLUGIN_NAME)/*
	@mkdir -p ../xcaddy-$(PLUGIN_NAME) && cd ../xcaddy-$(PLUGIN_NAME) && \
		xcaddy build v2.0.0-rc.3 --output ../$(PLUGIN_NAME)/bin/caddy \
		--with github.com/greenpau/caddy-auth-saml@$(GIT_COMMIT) \
		--with github.com/greenpau/caddy-auth-jwt@latest
	@#bin/caddy run -environ -config assets/conf/Caddyfile.json

linter:
	@echo "Running lint checks"
	@golint *.go
	@echo "PASS: golint"

test: covdir linter misc
	@go test $(VERBOSE) -coverprofile=.coverage/coverage.out ./*.go

ctest: covdir linter misc
	@time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./*.go

covdir:
	@echo "Creating .coverage/ directory"
	@mkdir -p .coverage

coverage:
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out ./*.go
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"

misc:
	@./assets/scripts/generate_ui.sh
	@python3 assets/scripts/test_app_signing_cert.py > assets/scripts/test_app_signing_cert.xml

docs:
	@mkdir -p .doc
	@go doc -all > .doc/index.txt
	@python3 assets/scripts/toc.py > .doc/toc.md

clean:
	@rm -rf .doc
	@rm -rf .coverage
	@rm -rf bin/

qtest:
	@echo "Perform quick tests ..."
	@#time richgo test -v -run TestPlugin ./*.go

dep:
	@echo "Making dependencies check ..."
	@go get -u golang.org/x/lint/golint
	@go get -u golang.org/x/tools/cmd/godoc
	@go get -u github.com/kyoh86/richgo
	@go get -u github.com/caddyserver/xcaddy/cmd/xcaddy
	@pip3 install Markdown --user
	@pip3 install markdownify --user
	@pip3 install signxml --user
	@go get -u github.com/greenpau/versioned/cmd/versioned


release:
	@echo "Making release"
	@if [ $(GIT_BRANCH) != "master" ]; then echo "cannot release to non-master branch $(GIT_BRANCH)" && false; fi
	@git diff-index --quiet HEAD -- || ( echo "git directory is dirty, commit changes first" && false )
	@versioned -patch
	@echo "Patched version"
	@git add VERSION
	@git commit -m "released v`cat VERSION | head -1`"
	@git tag -a v`cat VERSION | head -1` -m "v`cat VERSION | head -1`"
	@git push
	@git push --tags
	@#git push --delete origin vX.Y.Z
	@#git tag --delete vX.Y.Z
