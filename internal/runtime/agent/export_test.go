package agent

// DeleteHelperForTest exposes deleteHelper to the external tests.
func (b *Backend) DeleteHelperForTest(id string) { b.deleteHelper(id) }
