AGENT ?= agent-1
TEXT ?= hello
INPUT ?= {}
export AGENT TEXT INPUT ACTION PLUGIN

.PHONY: help build test test-e2e test-race certs agent server client-1 client-2 dev-plugins status echo host-facts disk-usage service-health uptime run plugin-add health-service plugins clean
help:
	@echo 'Make targets:'
	@echo '  make help                 Show this help (also the default)'
	@echo '  make certs                Create local development CA, server, and agent-1 certificates'
	@echo '  make agent NAME=agent-2   Create and authorize another development agent'
	@echo '  make server               Build and start the server'
	@echo '  make client-1             Build and start agent-1'
	@echo '  make client-2             Build and start agent-2'
	@echo '  make dev-plugins          Prepare signed development plugins'
	@echo '  make build                Build server, client, control, and release binaries'
	@echo '  make test                 Run Go tests'
	@echo '  make test-e2e             Run mTLS and plugin lifecycle tests'
	@echo '  make test-race            Run tests with the race detector'
	@echo '  make plugins              List installed and active plugins on AGENT'
	@echo '  make status / echo        Run a plugin on AGENT (default agent-1)'
	@echo '  make host-facts / disk-usage / service-health  Run example actions'
	@echo '  make plugin-add           Publish and activate the new uptime plugin'
	@echo '  make health-service       Start a local HTTP service for service-health'
	@echo '  make uptime               Run the added plugin'
	@echo '  make run ACTION=... INPUT=... AGENT=...  Run another action'
	@echo '  make clean                Remove built binaries'
	@echo ''
	@echo 'Run server and clients in separate terminals. Type help at the server prompt for server commands.'
build:
	mkdir -p bin
	go build -o bin/bidi-server ./cmd/bidi-server
	go build -o bin/bidi-client ./cmd/bidi-client
	go build -o bin/bidi-control ./cmd/bidi-control
	go build -o bin/plugin-release ./cmd/plugin-release
test:
	go test ./...
test-e2e:
	go test -count=1 -v ./internal/server
test-race:
	go test -race ./...
certs:
	bash scripts/dev-certs.sh
agent:
	bash scripts/add-agent.sh "$(NAME)"
dev-plugins:
	bash scripts/dev-plugins.sh
server: build dev-plugins
	./bin/bidi-server -catalog .dev-plugins/catalog.json -permissions .dev-plugins/permissions.json -control-socket .dev-plugins/control.sock
client-1: build dev-plugins
	./bin/bidi-client -name agent-1 -cert certs/agent.crt -key certs/agent.key -plugin-dir .dev-plugins/agent-1 -publisher-keys .dev-plugins/publisher-keys.json -plugin-allow status,echo,host-facts,disk-usage,service-health,uptime -plugin-read-paths /tmp -plugin-services .dev-plugins/services.json
client-2: build dev-plugins
	./bin/bidi-client -name agent-2 -cert certs/agent-2.crt -key certs/agent-2.key -plugin-dir .dev-plugins/agent-2 -publisher-keys .dev-plugins/publisher-keys.json -plugin-allow status,echo,host-facts,disk-usage,service-health,uptime -plugin-read-paths /tmp -plugin-services .dev-plugins/services.json
plugins status echo host-facts disk-usage service-health uptime run: build
	@case "$@" in \
	  plugins) ./bin/bidi-control -agent "$$AGENT" -operation plugins ;; \
	  status) ./bin/bidi-control -agent "$$AGENT" -action status ;; \
	  echo) ./bin/bidi-control -agent "$$AGENT" -action echo -input "$$TEXT" ;; \
	  host-facts) ./bin/bidi-control -agent "$$AGENT" -action host-facts.snapshot ;; \
	  disk-usage) ./bin/bidi-control -agent "$$AGENT" -action disk-usage.measure -input '{"path":"/tmp"}' ;; \
	  service-health) ./bin/bidi-control -agent "$$AGENT" -action service-health.check -input '{"service_id":"local-http"}' ;; \
	  uptime) ./bin/bidi-control -agent "$$AGENT" -action uptime.get ;; \
	  run) ./bin/bidi-control -agent "$$AGENT" -action "$$ACTION" -input "$$INPUT" ;; \
	esac
health-service:
	python3 -m http.server 18080 --bind 127.0.0.1 --directory examples/service-health
plugin-add: build dev-plugins
	bash scripts/dev-plugin-add.sh
clean:
	rm -f bin/bidi-server bin/bidi-client bin/bidi-control bin/plugin-release
