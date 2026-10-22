module github.com/Kate-0713/pihole-rbac

go 1.27.3

// npm packages occasionally ship .go files; keep `go test ./...` and `go vet ./...` out of node_modules.
ignore ./web/node_modules
