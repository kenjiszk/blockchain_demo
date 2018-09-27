package main

import(
	"math/big"
	"log"
	"bytes"
	"crypto/sha256"
)

func main() {
	log.Println("AAA")
	headers := bytes.Join([][]byte{[]byte{}, []byte{}, []byte{}}, []byte{})
	hash := sha256.Sum256(headers)
	log.Println(hash)
	log.Println(hash[:])

	target := big.NewInt(1)
	log.Println(target)
	// targetBits := 254
	target.Lsh(target, uint(29))
	log.Println(target)

}
