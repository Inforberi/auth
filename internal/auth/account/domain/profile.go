package domain

import "time"

type Profile struct {
	UserID      UserID
	FirstName   *string
	MiddleName  *string
	LastName    *string
	PhoneNumber *string
	AvatarURL   *string
	DisplayName *string
	Timezone    *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
