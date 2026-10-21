package domain

// PlatformActor is audit attribution, not proof of current authority.
type PlatformActor struct {
	RealmID ID
	UserID  ID
}

func (a PlatformActor) Valid() bool { return ValidID(a.RealmID) && ValidID(a.UserID) }
