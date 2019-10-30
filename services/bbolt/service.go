package bbolt

import (
	"fmt"

	bbolt "go.etcd.io/bbolt"
)

const (
	keysDB = "keys"
)

type Datastore interface {
	GetKey([]byte) ([]byte, error)
	InsertKey([]byte, []byte) error
	Close() error
}

type db struct {
	*bbolt.DB
}

// NewDB - build a new connection to BBolt
func NewDB(path string) (Datastore, error) {
	bDb, err := bbolt.Open(path, 0666, nil)
	if err != nil {
		return (*db)(nil), err
	}

	if err := bDb.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(keysDB))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		return nil
	}); err != nil {
		return (*db)(nil), err
	}

	return &db{DB: bDb}, nil
}

// GetKey - return a value for a given key
func (db *db) GetKey(key []byte) ([]byte, error) {
	var value []byte

	if err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(keysDB))
		v := b.Get(key)

		value = v

		return nil
	}); err !=  nil {
		return nil, err
	}

	return value, nil
}

func (db *db) InsertKey(key []byte, val []byte) error {
	if err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(keysDB))
		err := b.Put(key, val)

		return err
	}); err != nil {
		return err
	}

	return nil
}

// Close - return a deferable function for closing the db
func (db *db) Close() error {
	return db.DB.Close()
}
