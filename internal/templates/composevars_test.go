package templates

import (
	"maps"
	"slices"
	"testing"
)

func TestComposeVars(t *testing.T) {
	compose := `x-common: &common
  restart: ${RESTART_POLICY:-always}
x-env: &env
  SHARED: ${SHARED_ENV}
services:
  web:
    <<: *common
    image: app:${IMAGE_TAG}
    privileged: ${PRIV}
    user: "${RUN_AS}"
    labels:
      traefik.http.routers.web.rule: Host(` + "`${ROUTE_HOST}`" + `)
    volumes:
      - ${DATA_DIR:-./data}:/data
    environment:
      <<: *env
      LOG_LEVEL: ${LOG_LEVEL}
      BOTH: ${BOTH_VAR}
      NESTED: ${OUTER:-${INNER}}
      ${KEY_VAR}: x
      ESC: $${NOT_A_REF}
  worker:
    image: w
    environment:
      - "WORKER_MODE=${WORKER_MODE}"
    volumes:
      - ${BOTH_VAR}:/both
secrets:
  token:
    file: ${SECRET_FILE}
`
	u := ComposeVars([]byte(compose))
	if u.Err != "" {
		t.Fatal(u.Err)
	}
	// SHARED_ENV is also written in a top-level x- block (its anchor):
	// outside, although only environment: uses it (fail closed).
	wantEnv := []string{"INNER", "LOG_LEVEL", "OUTER", "WORKER_MODE"}
	if got := slices.Sorted(maps.Keys(u.EnvOnly)); !slices.Equal(got, wantEnv) {
		t.Errorf("EnvOnly %v, want %v", got, wantEnv)
	}
	for _, n := range []string{"RESTART_POLICY", "IMAGE_TAG", "PRIV", "RUN_AS", "ROUTE_HOST", "DATA_DIR", "BOTH_VAR", "KEY_VAR", "SECRET_FILE", "SHARED_ENV"} {
		if !u.Outside[n] || u.EnvOnly[n] {
			t.Errorf("%s: outside %v, env-only %v", n, u.Outside[n], u.EnvOnly[n])
		}
	}
	if u.Outside["NOT_A_REF"] || u.EnvOnly["NOT_A_REF"] {
		t.Error("$$ read as a reference")
	}
	if u := ComposeVars([]byte("services: [")); u.Err == "" {
		t.Error("a compose file that doesn't parse")
	}
}
