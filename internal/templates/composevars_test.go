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

// Allowlist fixes: list-form items, bare names, merge lists, anchors,
// operators, top-level sections, multiple documents, the visit budget.
func TestComposeVarsForms(t *testing.T) {
	cases := []struct {
		name     string
		compose  string
		env, out []string
	}{
		{"list item ${X} alone", "services:\n  a:\n    environment:\n      - ${X}\n", nil, []string{"X"}},
		{"list item ${X}=v", "services:\n  a:\n    environment:\n      - ${X}=v\n", nil, []string{"X"}},
		{"list item FOO${X}=v", "services:\n  a:\n    environment:\n      - FOO${X}=v\n", nil, []string{"X"}},
		{"list item FOO=${X}", "services:\n  a:\n    environment:\n      - FOO=${X}\n", []string{"X"}, nil},
		{"list item bare FOO", "services:\n  a:\n    environment:\n      - FOO\n", []string{"FOO"}, nil},
		{"map key without value", "services:\n  a:\n    environment:\n      FOO:\n      BAR: null\n", []string{"BAR", "FOO"}, nil},
		{"merge list", "x-a: &a {A: \"${A1}\"}\nx-b: &b {B: \"${B1}\"}\nservices:\n  s:\n    environment:\n      <<: [*a, *b]\n      C: ${C1}\n", []string{"C1"}, []string{"A1", "B1"}},
		{"anchor in environment aliased into labels", "services:\n  s:\n    environment:\n      V: &v \"${ANCH}\"\n    labels:\n      l: *v\n", nil, []string{"ANCH"}},
		{"$X without braces", "services:\n  s:\n    environment:\n      V: $PLAIN\n    image: img:$TAG\n", []string{"PLAIN"}, []string{"TAG"}},
		{"operators", "services:\n  s:\n    environment:\n      A: ${P1:+on}\n      B: ${P2?need it}\n      C: ${P3:?need it}\n    image: \"x:${P4:+y}${P5?z}\"\n", []string{"P1", "P2", "P3"}, []string{"P4", "P5"}},
		{"top-level sections", "name: ${PROJ}\nservices:\n  s:\n    image: x\nnetworks:\n  n: {name: \"${NET}\"}\nvolumes:\n  v: {name: \"${VOL}\"}\nconfigs:\n  c: {file: \"${CFG}\"}\n", nil, []string{"CFG", "NET", "PROJ", "VOL"}},
		{"cap_add default", "services:\n  scrutiny:\n    image: x\n    cap_add:\n      - ${SCRUTINY_NVME_CAPABILITY:-SYS_RAWIO}\n", nil, []string{"SCRUTINY_NVME_CAPABILITY"}},
		{"build args without value", "services:\n  s:\n    build:\n      context: .\n      args:\n        - BASE\n        - TAG=1\n  t:\n    build:\n      context: .\n      args:\n        BASE2:\n        BASE3: null\n        SET: x\n", nil, []string{"BASE", "BASE2", "BASE3"}},
		{"secret and config environment", "services:\n  s:\n    image: x\n    build:\n      context: .\n      secrets: [{id: b, environment: BUILD_SECRET}]\nsecrets:\n  tok: {environment: TOP_SECRET}\nconfigs:\n  c: {environment: TOP_CONFIG}\n", nil, []string{"BUILD_SECRET", "TOP_CONFIG", "TOP_SECRET"}},
	}
	for _, c := range cases {
		u := ComposeVars([]byte(c.compose))
		if u.Err != "" {
			t.Errorf("%s: %s", c.name, u.Err)
			continue
		}
		if got := slices.Sorted(maps.Keys(u.EnvOnly)); !slices.Equal(got, c.env) && !(len(got) == 0 && len(c.env) == 0) {
			t.Errorf("%s: EnvOnly %v, want %v", c.name, got, c.env)
		}
		for _, n := range c.out {
			if !u.Outside[n] || u.EnvOnly[n] {
				t.Errorf("%s: %s not outside (%+v)", c.name, n, u)
			}
		}
	}
	if u := ComposeVars([]byte("services: {}\n---\nservices: {}\n")); u.Err == "" {
		t.Error("two YAML documents accepted")
	}
	// An alias bomb: over the visit budget, fail closed.
	bomb := "a: &a [\"${X}\",\"${X}\",\"${X}\",\"${X}\",\"${X}\",\"${X}\",\"${X}\",\"${X}\",\"${X}\",\"${X}\"]\n"
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g"} {
		bomb += n + ": &" + n + " [*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + "]\n"
		prev = n
	}
	bomb += "services: {}\n"
	if u := ComposeVars([]byte(bomb)); u.Err == "" {
		t.Error("an alias bomb was walked to its end")
	}
}
