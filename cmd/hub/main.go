// Command hub is the Portcullis Hub: a web UI that manages per-app docker
// compose projects for the Portcullis auth gateway.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/httpapi"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	secret := os.Getenv("HUB_PROXY_SECRET")
	if err := httpapi.CheckSecret(secret); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	projectDir := env("PROJECT_DIR", "/project")
	cfg := hub.Config{
		ProjectDir:          projectDir,
		ProjectHostDir:      env("PROJECT_HOST_DIR", projectDir),
		DataDir:             env("HUB_DATA_DIR", filepath.Join(projectDir, ".hub")),
		Domain:              env("PORTCULLIS_DOMAIN", "portcullis.local"),
		DefaultTemplatesURL: os.Getenv("DEFAULT_TEMPLATES_URL"),
	}
	if v := os.Getenv("HUB_RECONCILE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 5*time.Second {
			log.Fatalf("HUB_RECONCILE_INTERVAL must be a duration >= 5s, got %q", v)
		}
		cfg.ReconcileInterval = d
	}

	dockerHost := env("DOCKER_HOST", docker.DefaultHost)
	engine, err := docker.New(dockerHost)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	kc := keycloak.New(env("KEYCLOAK_URL", "http://keycloak:8080"), os.Getenv("KEYCLOAK_ADMIN"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"))

	h, err := hub.New(cfg, compose.NewCLI(dockerHost), engine, kc)
	if err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	h.Init()

	srv := &httpapi.Server{
		Hub:        h,
		Users:      kc,
		PortalName: os.Getenv("PORTAL_DISPLAY_NAME"),
		Secret:     secret,
		Web:        web.FS,
	}
	handler, err := srv.Handler()
	if err != nil {
		log.Fatalf("ui: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go h.RunReconciler(ctx)

	addr := env("HUB_LISTEN_ADDR", ":8888")
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdown)
	}()
	log.Printf("Hub listening on %s (domain: %s, docker: %s)", addr, cfg.Domain, dockerHost)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
