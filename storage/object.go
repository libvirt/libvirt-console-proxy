package storage

type Object interface {
	Serialize() (string, error)
	Deserialize(string) error
}
