package folderfix

import "fmt"

// Usage measures a volume or bind for the Hub's storage view (contract
// §6, the usage mode): the fixer's walk (symlinks never followed, mount
// points counted and not crossed), regular files measured from their
// fstatat alone, never opened. It changes nothing. Entries that couldn't
// be read make it partial ("failed"), not a failure: the figure is a
// lower bound.
func Usage(o Options) (*Report, error) {
	idle := setIdleIO()
	w, err := openWalker(o, "usage")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	w.statOnly = true
	w.run(nil)
	r := w.finish()
	r.IOIdle = &idle
	if r.Failed.N > 0 && !r.Partial {
		r.Partial, r.PartialReason = true, "failed"
	}
	return r, nil
}

// usageOptions checks a usage run's options: a root and the caps only.
func usageOptions(o Options) error {
	if o.Target.GID != 0 || o.Target.OwnerUID != nil || len(o.Principals) > 0 || o.Children || o.ExpectDev != 0 || o.ExpectIno != 0 {
		return fmt.Errorf("usage takes only --root, --max-entries and --max-time")
	}
	return nil
}
