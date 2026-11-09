package templates

import (
	"maps"
	"slices"
	"testing"
)

func TestComposeMountVars(t *testing.T) {
	compose := `services:
  web:
    image: x
    volumes:
      - ${DATA_DIR:-./data}:/data
      - type: bind
        source: $CONF_DIR
        target: /conf
      - cache:/cache
    env_file: ["${ENV_FILE}", {path: "${ENV2}", required: false}]
    build: {context: "${CTX}", dockerfile: "${DF:-Dockerfile}"}
    network_mode: "service:${NET_SVC}"
    environment:
      LOG_LEVEL: ${LOG_LEVEL}
      ESC: $${NOT_A_REF}
  other:
    image: y
    pid: ${PID_MODE}
    ipc: ${IPC_MODE}
    build: ${CTX2}
    env_file: ${ENV3}
volumes:
  cache:
    driver_opts: {type: none, o: bind, device: "${DEVICE}"}
`
	got, err := ComposeMountVars([]byte(compose))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CONF_DIR", "CTX", "CTX2", "DATA_DIR", "DEVICE", "DF", "ENV2", "ENV3", "ENV_FILE", "IPC_MODE", "NET_SVC", "PID_MODE"}
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, want) {
		t.Errorf("mount vars %v, want %v", keys, want)
	}
	if _, err := ComposeMountVars([]byte("services: [")); err == nil {
		t.Error("a compose file that doesn't parse")
	}
}
