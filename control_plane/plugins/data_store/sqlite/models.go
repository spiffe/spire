package main

//go:generate go-bindata -pkg $GOPACKAGE -o migrations.go -prefix _migrations/ _migrations/

import (
	"github.com/jinzhu/gorm"
	"time"
)

type federatedBundle struct {
	gorm.Model
	SpiffeId string
	Bundle   []byte
	Ttl      int32
}

type attestedNodeEntry struct {
	gorm.Model
	SpiffeId     string
	DataType     string
	SerialNumber string
	ExpiresAt    time.Time
}

type nodeResolverMapEntry struct {
	gorm.Model
	SpiffeId string
	Type     string
	Value    string
}

type registeredEntry struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	RegisteredEntryId string `gorm:"primary_key:true"`
	SpiffeId          string
	ParentId          string
	Ttl               int32
	Selectors         []*selector
	// TODO: Add support to Federated Bundles [https://github.com/spiffe/sri/issues/42]
}

type selector struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	RegisteredEntryId string `gorm:"primary_key:true"`
	Type              string `gorm:"primary_key:true"`
	Value             string `gorm:"primary_key:true"`
	RegisteredEntry   registeredEntry
}

func migrateDB(db *gorm.DB) error {
	for _, name := range AssetNames() {
		migration, err := Asset(name)
		if err != nil {
			return err
		}
		if _, err := db.DB().Exec(string(migration)); err != nil {
			return err
		}
	}

	return nil
}
