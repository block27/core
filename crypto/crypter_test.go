package crypto

import (
	"encoding/hex"
	"testing"
)

var crypter *Crypter

func init() {
	crypter, _ = NewCrypter(
		[]byte("hn8adjw4t6aa9fe57h4jku6p6mf8c2pw"),
		[]byte("q5nb45yf83cna97z"),
	)
}

func TestDigestMD5Sum(t *testing.T) {
	if hex.EncodeToString(DigestMD5Sum([]byte("hello"))) != "5d41402abc4b2a76b9719d911017c592" {
		t.Fail()
	}
}

func TestDigestSHA1Sum(t *testing.T) {
	if hex.EncodeToString(DigestSHA1Sum([]byte("hello"))) != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" {
		t.Fail()
	}
}

func TestDigestSHA256Sum(t *testing.T) {
	if hex.EncodeToString(DigestSHA256Sum([]byte("hello"))) != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fail()
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Test against a 9 sized block
	r4, e4 := crypter.Encrypt([]byte(LoremIpsum))
	if  e4 !=nil {
		t.Fail()
	}  else {
		d4, _ := crypter.Decrypt(r4)

		if string(d4) != LoremIpsum {
			t.Fail()
		}
	}

	// Test against a 9 sized block
	r3, e3 := crypter.Encrypt([]byte(Block9))
	if  e3 !=nil {
		t.Fail()
	}  else {
		d3, _ := crypter.Decrypt(r3)

		if string(d3) != Block9 {
			t.Fail()
		}
	}

	// Test against a 333 sized block
	r2, e2 := crypter.Encrypt([]byte(Block333))
	if  e2 !=nil {
		t.Fail()
	}  else {
		d2, _ := crypter.Decrypt(r2)

		if string(d2) != Block333 {
			t.Fail()
		}
	}

	// Test against a 1024 sized block
	r1, e1 := crypter.Encrypt([]byte(Block1024))
	if  e1 !=nil {
		t.Fail()
	}  else {
		d1, _ := crypter.Decrypt(r1)

		if string(d1) != Block1024 {
			t.Fail()
		}
	}
}

var Block9 = `IjhO1df8U/ux`

var Block333 = `
C49TEsEOQ7eVnUrjvt4h5D+672XYo8WMtkIoHhCpzNUbV5EGJuWTLzLph6kSXMTR
nISmgYWyoT2Te1Lb67b71mTkpy0rRcqM8AlfM3tuGzG8zAzUFhVVLA7IuTVWxpZA
EyLa2UpPeUgX+8cJkO3dFiMS4o9Yca6dv9xKWKnzTxfBXPvZrv8MLbenJ3OmlG4F
P3Xs+sIIfW+1mVmb1VTcC758PDWYxQjPV+3ftfPiohgZapeGnFmOyc8rZampvsiD
LU7lWuxHMfu/LGHVAbiwN3lwDuzmeG5wa5cnVB8Kior/i0mTf0/RTI/oPn4AoT9h
2Ncrf8AeboANEhL5o1oW0cXqdw53e30jpnQ+OK4ZKO+Wg16l8eqQZAvVK5mhMisN
NyU5jUFhdY40BuKpAU+bgACJW5qY/iqqFVkuaqCpwEtf1cs7LCNh0uqRfJDM
`

var Block1024 = `
7C3jv423Cralcc6Iyrwt8YmKfUfV9WKCjB7D22rFr7XH/lClzjHxuVQEgUUp1WMT
3bXIzIyZV9MvvGYTJfCn1m4h7aV/Gx8TcJqZWgeFIYoEYkwaZJdYW4JGg3rRm8b9
PCFvzhybP3v6dIgjycDG/NFh+HWeIkLhuoguTs+DIxpFD43eym7Zr9hNJeunS0nm
wpjenv4hl3teBchzFNjwHFSWNq6QaRrmAHuDf7s+hz7xdbyUOYJ9MHFaXzEBFmSv
kkkPfvS1bKKUFtmOGKPHhzhRMSHpmOHxi5ESHM14uGf6u3pIStugVykmYlJ4nN0q
xwx3BrpL9pZY79K2NvODACrxOBYXAYLDCnn4nq1npovSLmLF1DqSRbBMASe/LW4b
N2GbjlLXas3zdXai87+HulGB7qUL0WqowJs915KrF9arXL0ojvjyrcH8YxTJdLz6
UzbdYwtlCH0GbcL6WXRo1VZqLNa1JVrbBeIh20OK8XH3VW/P37uFWdu9jKKQMgTG
mlMaNQtbfnhDyajWalYzMV6dXXZ4bjyzEAkHenAS7CUr6AIzdAdqN4fjqQP923tC
doJxAxREle0Pwx+/1j+80I/c6npAJU6PzMfoS9rNp37q8jOveOCqBekTrikGE/MH
DC/qxYB0FcgwuXuAmSo3Ds0iK7rsZ+A2y85FGCe7HdAJixrgqqEoS8UL3PrEK47R
4ThQ4uSZntysOKd3CM4/YhO/cXoNAGkvkaW3efwHy79flrPoxcA0kd6Q+2EBE+jT
zqQ+adbpwclBeuIMXAyge6b2QL2rfj/0g6KybSDELndn3TFPmq7CwnLpZW7LPBhN
klCbuZqAVEAh07Vacy6zoIRPGcEYiZgVyIbt2zqlP+sAGFwnnNK56L2/ZUIIIm2h
CmhVHoOnYPAVkpVRfRpbkzz++pPQff/2qikZCzlroNL1fQmQ/pPH/rT4n/qsRhL/
XCxkQPrGGlDf9Cc2KyohWLw9IsmqJtBSJc0rWLd0QMmKLvMKmhDmdhvX+YsYzg7+
4uIGC49Aw1KviKZ+Sk+IF5hKx4/zJM0BFky80sXYbBER5b7cqj1TOdiclkbdRb4W
kpTcrMmxmuqBY0foB9auR88rhN4AXk7zsG/RnmhCltqPZM0DB+7/PGDM5Ch6o9aN
pncQalJZCq94vjLB/jdLsLROQ4bI5M6nLHIwBGZyXcM/WgNETWuYPWNJ/oEqayNN
icGEvpmbq9OavXuYoiZ6aaEqDrbdRKEMO7qafQ54VpVaM+4R3aTluvo/xkU+0WiP
3HLOCE3ETE516/XvYpyCUWsr9fja/zUz7Q5phcSyxNBnosUQsJzCon+9VK8LbLjV
FMZaVvtKa+VsNSIc60JP4A==
`

var LoremIpsum = `
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut
enim ad minim veniam, quis nostrud exercitation ullamco laboris
nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor
in reprehenderit in voluptate velit esse cillum dolore eu fugiat
nulla pariatur. Excepteur sint occaecat cupidatat non proident,
sunt in culpa qui officia deserunt mollit anim id est laborum.
`
