package errors


//------------------------------------------------------------------------------

// KeyPathAPI ...
type KeyPathAPI interface {
	Error() string
}

// KeyPath ...
type KeyPath struct{
	Message string
}

// NewKeyPathError ...
func NewKeyPathError(message string) KeyPathAPI {
	return &KeyPath{
		Message: message,
	}
}

func (k *KeyPath) Error() string {
    return k.Message
}


//------------------------------------------------------------------------------

// KeyObjtAPI ...
type KeyObjtAPI interface {
	Error() string
}

// KeyObjt ...
type KeyObjt struct{
	Message string
}

// NewKeyObjtError ...
func NewKeyObjtError(message string) KeyObjtAPI {
	return &KeyObjt{
		Message: message,
	}
}

func (k *KeyObjt) Error() string {
    return k.Message
}
