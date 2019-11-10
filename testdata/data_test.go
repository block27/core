package testdata

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/amanelis/bespin/helpers"
)

func TestSHADummy(t *testing.T) {
	data := helpers.ReadBinary("./dummy.pdf")
	summ := fmt.Sprintf("%x", sha256.Sum256(data))

	if summ != "3df79d34abbca99308e79cb94461c1893582604d68329a41fd4bec1885e6adb4" {
		t.Fail()
	}
}

func TestMD5Dummy(t *testing.T) {
	data := helpers.ReadBinary("./dummy.pdf")
	sigs := md5.Sum(data)
	summ := fmt.Sprintf("%x", hex.EncodeToString(sigs[:]))

	if summ != "3239343262666162623364303533333262363665623132386530383432636666" {
		t.Fail()
	}
}

func TestSHARandom(t *testing.T) {
	data := helpers.ReadBinary("./random")
	summ := fmt.Sprintf("%x", sha256.Sum256(data))

	if summ != "ed43ab83803407994484de86803284b39fcf0fc31185c5114bf3741c3514c613" {
		t.Fail()
	}
}

func TestMD5Random(t *testing.T) {
	data := helpers.ReadBinary("./random")
	sigs := md5.Sum(data)
	summ := fmt.Sprintf("%x", hex.EncodeToString(sigs[:]))

	if summ != "6434396665663461343264373730356431386638373930646330316339656232" {
		t.Fail()
	}
}

func TestSHABig(t *testing.T) {
	data := helpers.ReadBinary("./big")
	summ := fmt.Sprintf("%x", sha256.Sum256(data))

	if summ != "81110928e7103ca0a8b1648930f15056f015a59cdf9c035cb3e7795ff84a6ac0" {
		t.Fail()
	}
}

func TestMD5Big(t *testing.T) {
	data := helpers.ReadBinary("./big")
	sigs := md5.Sum(data)
	summ := fmt.Sprintf("%x", hex.EncodeToString(sigs[:]))

	if summ != "3233383664353337336162396230346539356463323366613836343539656530" {
		t.Fail()
	}
}
