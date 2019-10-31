package bbolt

import (
	"fmt"

	bbolt "go.etcd.io/bbolt"
)

const (
	keysDB = "keys"
)

// Datastore ...
type Datastore interface {
	AllKeys() ([][]byte, error)
	GetVal([]byte) ([]byte, error)
	InsertKey([]byte, []byte) error
	Close() error
}

// db ...
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

// AllKeys - returns a byte slice of all keys
func (db *db) AllKeys() ([][]byte, error) {
	var value [][]byte

	if err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(keysDB))
		c := b.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			value = append(value, k)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return value, nil
}

// GetVal - return a value for a given key
func (db *db) GetVal(key []byte) ([]byte, error) {
	var value []byte

	if err := db.View(func(tx *bbolt.Tx) error {
		value = tx.Bucket([]byte(keysDB)).Get(key)

		return nil
	}); err != nil {
		return nil, err
	}

	return value, nil
}

// InsertKey - insert a key/value pair into a given bucket
func (db *db) InsertKey(key []byte, val []byte) error {
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(keysDB)).Put(key, val)
	}); err != nil {
		return err
	}

	return nil
}

// Close - return a deferable function for closing the db
func (db *db) Close() error {
	return db.DB.Close()
}
