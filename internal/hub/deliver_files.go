package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Data files (contract §13.7, spec call 14): <appfiles>/<id>/<name>/
// <name>.json (0640: the reader runs as root or with group 10001) and,
// when the file carries secret options, <name>.secrets.json (0600: root
// or uid 10001 only) in the same directory. The override bind-mounts the
// directory read-only at the file's mount, never the single file: an
// atomic rename gives the file a new inode, which a file bind mount would
// not show until the container restarts.

// Modes of the data file tree.
const (
	appFilesDirMode = 0750
	dataFileMode    = 0640
	secretsFileMode = 0600
)

// appFilesDir is instance id's data file root (Hub side).
func (h *Hub) appFilesDir(id string) string { return filepath.Join(h.cfg.AppFilesDir, id) }

// dataFileDir is the directory of data file name (mounted at its mount).
func (h *Hub) dataFileDir(id, name string) string { return filepath.Join(h.appFilesDir(id), name) }

func (h *Hub) dataFilePath(id, name string) string {
	return filepath.Join(h.dataFileDir(id, name), name+".json")
}

func (h *Hub) secretsFilePath(id, name string) string {
	return filepath.Join(h.dataFileDir(id, name), name+".secrets.json")
}

// forgetDeliveries removes instance id's data files and delivery state
// (delete; <data>/settings/<id>/ goes with removeSecrets), holding its
// delivery lock: a run in progress finishes first, a queued one is
// dropped.
func (h *Hub) forgetDeliveries(id string) error {
	if !templates.ValidID(id) {
		return nil
	}
	l := h.deliverLock(id)
	l.Lock()
	defer l.Unlock()
	h.deliveryMu.Lock()
	if q := h.queued[id]; q != nil && q.stop != nil {
		q.stop()
	}
	delete(h.queued, id)
	delete(h.deliveryStatus, id)
	h.deliveryMu.Unlock()
	if err := os.Remove(h.deliveredPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.RemoveAll(h.appFilesDir(id))
}

// dataFileMounts are t's data file directories as override volume
// entries per service: "<host appfiles>/<id>/<name>:<mount>:ro" ($
// escaped as $$: compose interpolates the override).
func (h *Hub) dataFileMounts(t *templates.Template) map[string][]string {
	out := map[string][]string{}
	for _, f := range sortedFiles(t) {
		if f.Service == "" || f.Mount == "" || !templates.ValidID(t.ID) {
			continue
		}
		host := path.Join(filepath.ToSlash(h.cfg.AppFilesHostDir), t.ID, f.Name)
		vol := composeLiteral(host) + ":" + composeLiteral(f.Mount) + ":ro"
		b, _ := json.Marshal(vol)
		out[f.Service] = append(out[f.Service], string(b))
	}
	return out
}

// fileDeliveries are o's deliveries into data file name.
func fileDeliveries(o *templates.Option, name string) []templates.Delivery {
	var out []templates.Delivery
	for _, d := range o.Delivery {
		if d.File != nil && d.File.Name == name {
			out = append(out, d)
		}
	}
	return out
}

// fileNeedsPeople: data file name carries per-person, per-group or
// person-entered values (it needs the directory).
func fileNeedsPeople(t *templates.Template, name string) bool {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() != templates.ScopeInstance && len(fileDeliveries(&opts[i], name)) > 0 {
			return true
		}
	}
	return false
}

// filesNeedPeople: some data file of t needs the directory.
func filesNeedPeople(t *templates.Template) bool {
	for _, f := range t.Manifest.Files {
		if fileNeedsPeople(t, f.Name) {
			return true
		}
	}
	return false
}

// buildFilesLocked renders every data file of t (sorted by name) from
// state and snapshot m (nil: the directory unavailable — files that need
// it are skipped, not built). Caller holds mu (read).
func (h *Hub) buildFilesLocked(t *templates.Template, m *directory.Membership) []fileOutput {
	var out []fileOutput
	var people map[string]map[string]settings.Resolved
	var secrets map[string]string
	var secretsErr error
	secretsRead := false
	for _, f := range sortedFiles(t) {
		o := fileOutput{file: f, people: fileNeedsPeople(t, f.Name)}
		if o.people && m == nil {
			o.skip = SkipDirectory
			out = append(out, o)
			continue
		}
		if o.people && people == nil {
			people = h.resolvePeopleLocked(t, m)
		}
		if !secretsRead && fileHasSecret(t, f.Name) {
			secrets, secretsErr = h.secretValues(t.ID)
			secretsRead = true
		}
		if fileHasSecret(t, f.Name) && secretsErr != nil {
			o.err = secretsErr
			out = append(out, o)
			continue
		}
		o.data, o.secrets, o.err = h.renderDataFileLocked(t, f.Name, m, people, secrets)
		if o.err == nil {
			sum := sha256.New()
			sum.Write(o.data)
			sum.Write([]byte{0})
			sum.Write(o.secrets)
			o.hash = hex.EncodeToString(sum.Sum(nil))
		}
		out = append(out, o)
	}
	return out
}

// fileHasSecret: an instance secret option delivers into file name.
func fileHasSecret(t *templates.Template, name string) bool {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].Type == templates.TypeSecret && len(fileDeliveries(&opts[i], name)) > 0 {
			return true
		}
	}
	return false
}

// renderDataFileLocked renders data file name of t: instance values,
// per-person values of the population (UNRESOLVED values omitted, fail
// closed), group records whose group id matches snapshot m, and the
// secrets file (nil when the file carries no secret option). Errors
// never carry a secret. Caller holds mu (read).
func (h *Hub) renderDataFileLocked(t *templates.Template, name string, m *directory.Membership, people map[string]map[string]settings.Resolved, secrets map[string]string) (data, secretsDoc []byte, err error) {
	doc := settings.NewDataFileDoc(t.ID)
	s := h.st.Settings[t.ID]
	var sec map[string]string
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		ds := fileDeliveries(o, name)
		if len(ds) == 0 {
			continue
		}
		switch o.EffectiveScope() {
		case templates.ScopeInstance:
			if o.Type == templates.TypeSecret {
				if sec == nil {
					sec = map[string]string{}
				}
				if _, set := s.Secrets[o.Key]; set && secrets[o.Key] != "" {
					sec[o.Key] = secrets[o.Key]
				}
				continue
			}
			v, ok := h.effectiveValue(t, o, s)
			if !ok {
				continue
			}
			if str, isStr := v.(string); isStr && o.Type == templates.TypePath && strings.HasPrefix(str, folderPrefix) {
				continue // a mount, not a value
			}
			for _, d := range ds {
				r, err := settings.RenderDelivery(o, v, &d)
				if err != nil {
					return nil, nil, fmt.Errorf("setting %s: %w", o.Key, err)
				}
				doc.Values[o.Key] = r.JSON
			}
		case templates.ScopePerson:
			for _, user := range sortedUsers(people) {
				res, ok := people[user][o.Key]
				if !ok || res.Value == nil {
					// No value, or UNRESOLVED (ReasonFailClosed): omitted.
					continue
				}
				for _, d := range ds {
					r, err := settings.RenderDelivery(o, res.Value, &d)
					if err != nil {
						log.Printf("settings: %s: %s: the value of %s doesn't render (%v): omitted", t.ID, o.Key, user, err)
						continue
					}
					field := d.File.Field
					if field == "" {
						field = o.Key
					}
					if doc.People[user] == nil {
						doc.People[user] = map[string]any{}
					}
					doc.People[user][field] = r.JSON
				}
			}
		case templates.ScopeGroup:
			if !h.typeMatchesLocked(t, o.Key, o) {
				continue
			}
			recs := h.groupRecordsOut(t, o, s.Groups[o.Key], m)
			for _, d := range ds {
				list := make([]settings.GroupRecordOut, 0, len(recs))
				for _, r := range recs {
					rd, err := settings.RenderDelivery(o, r.Value, &d)
					if err != nil {
						return nil, nil, fmt.Errorf("setting %s: group %s: %w", o.Key, r.Group, err)
					}
					list = append(list, settings.GroupRecordOut{Group: r.Group, Value: rd.JSON})
				}
				doc.Groups[o.Key] = list
			}
		}
		// person_entered: the entries section (Task 15A).
	}
	if data, err = json.MarshalIndent(doc, "", "  "); err != nil {
		return nil, nil, err
	}
	data = append(data, '\n')
	if sec != nil {
		if secretsDoc, err = json.MarshalIndent(settings.SecretsFileDoc{Version: settings.DataFileVersion, Instance: t.ID, Secrets: sec}, "", "  "); err != nil {
			return nil, nil, errors.New("the secrets file could not be encoded")
		}
		secretsDoc = append(secretsDoc, '\n')
	}
	return data, secretsDoc, nil
}

func sortedUsers(p map[string]map[string]settings.Resolved) []string {
	out := make([]string, 0, len(p))
	for u := range p {
		out = append(out, u)
	}
	slices.Sort(out)
	return out
}

// fileOnDisk: o's data file (and secrets file, or its absence) is on
// disk exactly as o would write it.
func (h *Hub) fileOnDisk(id string, o fileOutput) bool {
	b, err := os.ReadFile(h.dataFilePath(id, o.file.Name))
	if err != nil || !bytes.Equal(b, o.data) {
		return false
	}
	s, err := os.ReadFile(h.secretsFilePath(id, o.file.Name))
	if o.secrets == nil {
		return errors.Is(err, os.ErrNotExist)
	}
	return err == nil && bytes.Equal(s, o.secrets)
}

// writeDataFile writes o atomically: the data file 0640, the secrets
// file 0600 (removed when the file no longer carries a secret option),
// their directories 0750. Errors carry no content.
func (h *Hub) writeDataFile(id string, o fileOutput) error {
	if !templates.ValidID(id) {
		return fmt.Errorf("invalid instance id")
	}
	for _, d := range []string{h.cfg.AppFilesDir, h.appFilesDir(id), h.dataFileDir(id, o.file.Name)} {
		if err := os.MkdirAll(d, appFilesDirMode); err != nil {
			return fmt.Errorf("data file %s: %w", o.file.Name, err)
		}
	}
	for _, d := range []string{h.appFilesDir(id), h.dataFileDir(id, o.file.Name)} {
		if err := os.Chmod(d, appFilesDirMode); err != nil {
			return fmt.Errorf("data file %s: %w", o.file.Name, err)
		}
	}
	// The secrets first: a reader never sees new values next to old
	// secrets for longer than it must.
	sp := h.secretsFilePath(id, o.file.Name)
	if o.secrets != nil {
		if err := fsutil.WriteFileAtomic(sp, o.secrets, secretsFileMode); err != nil {
			return fmt.Errorf("writing the secrets file of %s failed", o.file.Name)
		}
	} else if err := os.Remove(sp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing the secrets file of %s: %w", o.file.Name, err)
	}
	if err := fsutil.WriteFileAtomic(h.dataFilePath(id, o.file.Name), o.data, dataFileMode); err != nil {
		return fmt.Errorf("writing data file %s: %w", o.file.Name, err)
	}
	return nil
}
