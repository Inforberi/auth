package runtime

import (
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// Observe retires resident snapshots after a confirmed catalog change. It keeps
// no unbounded project watermark map; cold-open and operation authority remain SQL-owned.
func (r *Registry) Observe(realm domain.ID, change domain.TransitionReceipt) {
	if !domain.ValidID(realm) || !domain.ValidID(change.ProjectID) || change.Version < 1 || change.Generation < 1 {
		return
	}
	r.mu.Lock()
	var idle []*entry
	for key, e := range r.entries {
		if key.Binding.RealmID != realm || key.Binding.ProjectID != change.ProjectID || e.retired {
			continue
		}
		older := key.Version < change.Version || key.Generation < change.Generation
		exact := key.Version == change.Version && key.Generation == change.Generation
		blocked := exact && (change.DesiredState != domain.Enabled || change.Phase != domain.Ready)
		if !older && !blocked {
			continue
		}
		e.retired = true
		if e.refs == 0 && e.pool != nil {
			idle = append(idle, e)
		}
	}
	r.signal()
	r.mu.Unlock()
	for _, e := range idle {
		r.dispose(e)
	}
}
