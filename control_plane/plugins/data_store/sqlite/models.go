package main

//go:generate go-bindata -pkg $GOPACKAGE -o migrations.go -prefix _migrations/ _migrations/

import (
	"time"

	"github.com/jinzhu/gorm"
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
