package templates

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose references to the reserved variables a file-sharing template
// reads (F36, contract §3.1 and §13.15 Variables):
//   - ${PORTCULLIS_LOCAL_NETWORKS} only in exactly that form: a default
//     or alternate (`:-`, `-`, `:+`, `+`, `:?`, `?`) or the bare
//     $PORTCULLIS_LOCAL_NETWORKS is refused, so no template default can
//     widen what the app allows when the list is empty;
//   - ${PORTCULLIS_FOLDER_GID_<KEY>} only as the whole value of a compose
//     environment: entry of the service that <KEY>'s folder block targets
//     (<KEY> a path option with a folder block); every other
//     PORTCULLIS_FOLDER_* reference is refused.

// varRef is one compose interpolation: the variable and whether it is
// exactly ${NAME}.
type varRef struct {
	name  string
	exact bool
}

// varRefs are the interpolations of compose value s ($$ is a literal $).
func varRefs(s string) []varRef {
	var out []varRef
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			i++
			continue
		}
		j := i + 1
		braced := j < len(s) && s[j] == '{'
		if braced {
			j++
		}
		k := j
		for k < len(s) && (s[k] == '_' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= 'a' && s[k] <= 'z' || s[k] >= '0' && s[k] <= '9') {
			k++
		}
		if k == j {
			continue
		}
		out = append(out, varRef{name: s[j:k], exact: braced && k < len(s) && s[k] == '}'})
	}
	return out
}

// ReferencesLocalNetworks: a value of compose reads
// ${PORTCULLIS_LOCAL_NETWORKS} (comments and $$ escapes don't count).
func ReferencesLocalNetworks(compose []byte) bool {
	var doc interface{}
	if yaml.Unmarshal(compose, &doc) != nil {
		return false
	}
	var scalars []string
	scalarValues(doc, &scalars)
	for _, s := range scalars {
		for _, r := range varRefs(s) {
			if r.name == VarLocalNetworks {
				return true
			}
		}
	}
	return false
}

// reservedVarRefs refuses compose references to the reserved variables
// outside their one allowed form (above).
func (v *specCheck) reservedVarRefs() error {
	// Folder gid variable → the services whose environment may read it.
	allowed := map[string][]string{}
	for _, o := range v.m.Options() {
		if o.Type == TypePath && o.Folder != nil && o.Target != nil && o.Target.Service != "" {
			allowed[FolderGIDVar(o.Key)] = append(allowed[FolderGIDVar(o.Key)], o.Target.Service)
		}
	}
	// How many environment values are exactly the allowed form.
	okCount := map[string]int{}
	for _, svc := range sortedServices(v.env) {
		for _, val := range v.env[svc] {
			if val == nil {
				continue
			}
			for name, svcs := range allowed {
				if *val == "${"+name+"}" && slices.Contains(svcs, svc) {
					okCount[name]++
				}
			}
		}
	}
	seen := map[string]int{}
	for _, s := range v.scalars {
		for _, r := range varRefs(s) {
			switch {
			case r.name == VarLocalNetworks:
				if !r.exact {
					return fmt.Errorf("compose.yml: %s may appear only as exactly ${%s} (no default or alternate form, no bare $%s)", VarLocalNetworks, VarLocalNetworks, VarLocalNetworks)
				}
			case strings.HasPrefix(r.name, varFolderPrefix):
				whole := s == "${"+r.name+"}" || strings.HasSuffix(s, "=${"+r.name+"}") && EnvKeyRe.MatchString(strings.TrimSuffix(s, "=${"+r.name+"}"))
				if !r.exact || !whole || len(allowed[r.name]) == 0 {
					return folderVarRefusal(r.name)
				}
				seen[r.name]++
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if seen[n] > okCount[n] {
			return folderVarRefusal(n)
		}
	}
	return nil
}

func folderVarRefusal(name string) error {
	return fmt.Errorf("compose.yml: %s is set by the Hub: only ${PORTCULLIS_FOLDER_GID_<KEY>} may be read, exactly so, as a whole environment: value of the service that <KEY>'s folder block targets", name)
}
