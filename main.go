package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"crypto/hmac"
	"crypto/sha256"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"encoding/binary"
)


var salt = "Fr)$FN^^$MSLG%NR-G!zDcvNCTHOvDXq"

func readline() string {
	bio := bufio.NewReader(os.Stdin)
	line, _, err := bio.ReadLine()
	if err != nil {
		fmt.Println(err)
	}
	return string(line)
}

func writeToFile(data []byte, file string) {
	if len(data) == 0 {
		fmt.Println("make sure your password is correct,there is nothing to write to the file")
	}

	ioutil.WriteFile(file, data, 777)
}

func readFromFile(file string) ([]byte, error) {
	data, err := ioutil.ReadFile(file)
	return data, err
}


func main() {

	var in, out string
	encryptCmd := flag.NewFlagSet("e", flag.ExitOnError)
	encryptCmd.StringVar(&in, "i", "", "input file name")
	encryptCmd.StringVar(&out, "o", "", "output file name if not provide it will be the same as the input file")

	decryptCmd := flag.NewFlagSet("d", flag.ExitOnError)
	decryptCmd.StringVar(&in, "i", "", "input file name")
	decryptCmd.StringVar(&out, "o", "", "output file name if not provide it will be the same as the input file")

	if len(os.Args) == 1 {
		fmt.Println("usage: encrypt <command> [<args>]")
		fmt.Println(" e  encrypt file")
		fmt.Println(" d  decrypt file ")
		return
	}
	//for help, flag default -h will show above info.
	switch os.Args[1] {
	case "e":
		encryptCmd.Parse(os.Args[2:])
	case "d":
		decryptCmd.Parse(os.Args[2:])
	default:
		//should print help info
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}

	if in == "" {
		fmt.Print("Missing required arguemnt to run the program, using -h for help")
		os.Exit(1)
	}

	if out == "" {
		out = in
	}

	fmt.Printf("Enter your password: ")
	maskedPassword, _ := gopass.GetPasswdMasked() // Masked
	fmt.Println(string(maskedPassword))

	key := generateKey(maskedPassword)

	if encryptCmd.Parsed() {
		plaintext, err := readFromFile(in)
		if err != nil {
			fmt.Printf("faild to read file, error : %s", err.Error())
		}
		ciphertext, _ := CBCEncrypter(key, plaintext)
		writeToFile(ciphertext, out)
		return
	}

	if decryptCmd.Parsed() {

		ciphertext, err := readFromFile(in)
		if err != nil {
			fmt.Println("File is not found")
			os.Exit(1)
		}
		plaintext, _ := CBCDecrypter(key, ciphertext)
		writeToFile(plaintext, out)
	}

}

//return mac, encryptedData
func getKeyData(message []byte) ([]byte, []byte, error) {
	if 4 > len(message) {
		return nil, nil, fmt.Errorf("CorruptedData ciphertextLen=%d", len(message))
	}

	//match key version
	mVerLenData := message[len(message)-4:]
	mVerLen := int(binary.LittleEndian.Uint32(mVerLenData))

	if mVerLen > len(message)-4 {
		return nil, nil, fmt.Errorf("CorruptedData keyVerLen=%d", mVerLen)
	}

	macLen := len(message)-mVerLen-4
	return message[:macLen],message[macLen:len(message)-4], nil
}


func CBCDecrypter(key, data []byte) ([]byte, error) {

        mac, ciphertext , _ :=getKeyData(data)
	fmt.Printf("mac's length:%d \n",len(mac))
	fmt.Printf("ciphertext's length:%d\n",len(ciphertext))
	//check if mac is the same.
        newMac :=computeHmac256(ciphertext,key)


	if !hmac.Equal(newMac,mac) {
		fmt.Println("hmac verify failed")
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return RemovePading(ciphertext)

}

//encrypt return   mac + encryptedData + 4 byte stores the length of encryptedData
func CBCEncrypter(key, plaintext []byte) ([]byte, error) {

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	paddedPlantext := AddPading(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(paddedPlantext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Printf("error: %s", err.Error())
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPlantext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to be secure.
	mac :=computeHmac256(ciphertext,key)
         fmt.Printf("mac's length:%d \n",len(mac))
	fmt.Printf("ciphertext's length:%d\n",len(ciphertext))
	//append the mac
	mac = append(mac, ciphertext...)

	//append the ciphertext length
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(len(ciphertext)))

	mac = append(mac, bs...)

	return mac, nil
}

// SHA256-HMAC (Keyed-Hash Message Authentication Code)
func computeHmac256(message, secretKey []byte) []byte {
	hasher := hmac.New(sha256.New, []byte(secretKey))
	hasher.Write([]byte(message))
	return hasher.Sum(nil)


}

// This implementation follows the recommendation in https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
func AddPading(data []byte) []byte {

	//always need a padding block
	padlen := aes.BlockSize - len(data)%aes.BlockSize

	//padlen as the value of padding
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...)
}

func RemovePading(data []byte) ([]byte, error) {

	if len(data)%aes.BlockSize != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len=%d", len(data))
	}

	padlen := int(data[len(data)-1])
	if padlen > aes.BlockSize || padlen == 0 {
		return nil, fmt.Errorf("invalid padding len=%d", padlen)
	}

	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding data at pos=%d", i)
		}
	}
	return data[:len(data)-padlen], nil
}

//method 1:using PBKDF2, ideally salt should be random generated but when decrypt how to know it. add in the data?
//now we just use the masterKey as salt.
func generateKey(password []byte) []byte {

	return pbkdf2.Key(password, []byte(salt), 4096, sha256.Size, sha256.New)
}

//method 2: bcrypt , not work, with this key the program just hanging there.
func generateKey2(password []byte) ([]byte, error) {

	return bcrypt.GenerateFromPassword(password, bcrypt.MaxCost)

}
