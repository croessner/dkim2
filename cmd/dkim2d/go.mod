module github.com/croessner/dkim2/cmd/dkim2d

go 1.26

require (
	github.com/croessner/dkim2 v0.0.0
	github.com/getkin/kin-openapi v0.135.0
	github.com/prometheus/client_golang v1.23.2
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/valkey-io/valkey-go v1.0.76
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.44.0
	go.opentelemetry.io/otel/sdk v1.44.0
	go.opentelemetry.io/otel/trace v1.44.0
	go.uber.org/fx v1.24.0
	go.yaml.in/yaml/v3 v3.0.4
	golang.org/x/sys v0.47.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/prometheus/common v0.66.1
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260608224507-4308a22a1bab // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260608224507-4308a22a1bab // indirect
)
