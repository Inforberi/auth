package domain

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var storageTargetPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

type CreationPolicy struct {
	AuthDomain     string
	StorageTarget  string
	PlatformOrigin string
}

func (p CreationPolicy) Valid() bool {
	return ValidOrigin("https://"+p.AuthDomain) && !strings.ContainsAny(p.AuthDomain, ":/") &&
		storageTargetPattern.MatchString(p.StorageTarget) && ValidOrigin(p.PlatformOrigin)
}

type Create struct {
	OperationID ID
	Slug        string
	Name        string
	Reason      string
}

type CreationReceipt struct {
	Project  Project
	Replayed bool
}

func (c Create) Normalize() (Create, error) {
	if !ValidID(c.OperationID) || !ValidSlug(c.Slug) || !validReason(c.Reason) {
		return Create{}, ErrInvalidProject
	}
	name, err := NormalizeName(c.Name)
	if err != nil {
		return Create{}, err
	}
	c.Name = name
	return c, nil
}

func (p CreationPolicy) Origin(slug string) (string, error) {
	origin := "https://" + slug + "." + p.AuthDomain
	if !ValidOrigin(origin) || origin == p.PlatformOrigin {
		return "", ErrInvalidProject
	}
	return origin, nil
}

func validReason(reason string) bool {
	return len(reason) > 0 && len(reason) <= 500 && utf8.ValidString(reason) &&
		strings.TrimSpace(reason) == reason && !strings.ContainsFunc(reason, unicode.IsControl)
}
