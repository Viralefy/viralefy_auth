// Package observability expõe os collectors Prometheus do viralefy_auth.
//
// Mantém os nomes de métricas idênticos ao viralefy_core
// (http_requests_total, http_request_duration_seconds) pra reaproveitar
// dashboards de Grafana sem mudanças — basta filtrar por label
// service=viralefy-auth no Prometheus.
package observability

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total de requests HTTP processados, com labels method, path, status.",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duração das requests HTTP em segundos.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	DBQueryDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Duração de queries SQL agrupadas por tipo lógico.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"query_type"},
	)
)

var (
	metricsRegistry *prometheus.Registry
	metricsOnce     sync.Once
)

// InitMetrics regista os collectors num Registry isolado (não polui o default).
// Idempotente — chamadas seguintes devolvem o mesmo Registry.
func InitMetrics() *prometheus.Registry {
	metricsOnce.Do(func() {
		reg := prometheus.NewRegistry()
		reg.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			HTTPRequestsTotal,
			HTTPRequestDurationSeconds,
			DBQueryDurationSeconds,
		)
		metricsRegistry = reg
	})
	return metricsRegistry
}

// MetricsHandler devolve o handler HTTP do /metrics. Use após InitMetrics.
func MetricsHandler() http.Handler {
	if metricsRegistry == nil {
		InitMetrics()
	}
	return promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Registry:          metricsRegistry,
	})
}

// statusRecorder envolve http.ResponseWriter pra capturar o status
// sem reimplementar tudo. Default 200 quando o handler não chama
// WriteHeader explicitamente.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// HTTPMiddleware instrumenta cada request com http_requests_total +
// http_request_duration_seconds. Usa r.Pattern (Go 1.22 ServeMux) quando
// disponível pra evitar explosão de cardinalidade — id na URL vira label.
// Fallback é "unknown" pra requests sem rota matched (404).
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// r.Pattern (Go 1.22 ServeMux) traz padrões registrados como
		// "GET /internal/v1/health" — recortamos o verbo+espaço pra ficar
		// igual ao formato chi.RoutePattern usado em core/payments/sender
		// e dashboards reusarem os mesmos labels.
		pathLabel := r.Pattern
		if i := strings.IndexByte(pathLabel, ' '); i >= 0 {
			pathLabel = pathLabel[i+1:]
		}
		if pathLabel == "" {
			pathLabel = "unknown"
		}
		statusStr := strconv.Itoa(rec.status)
		HTTPRequestsTotal.WithLabelValues(r.Method, pathLabel, statusStr).Inc()
		HTTPRequestDurationSeconds.WithLabelValues(r.Method, pathLabel).Observe(time.Since(start).Seconds())
	})
}

// ObserveDBQuery: shorthand para instrumentar uma query SQL.
//
//	defer observability.ObserveDBQuery("select_user")(time.Now())
func ObserveDBQuery(queryType string) func(start time.Time) {
	return func(start time.Time) {
		DBQueryDurationSeconds.WithLabelValues(queryType).Observe(time.Since(start).Seconds())
	}
}
