package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	encryptedFileName = "EncryptedFile.bin"
	decryptedFileName = "DecryptedFile"
	keyPattern        = "passphrasewhichneedstobe32bytes!"
)

var tpl *template.Template
var userKey = ""
var userDecrypt = ""
var downloadedKey = ""

func main() {
	http.Handle("/stuff/", http.StripPrefix("/stuff", http.FileServer(http.Dir("./static/"))))
	http.HandleFunc("/", encr)
	http.HandleFunc("/goto1", decr)
	http.HandleFunc("/goto2", encr)
	http.HandleFunc("/uploadFile", uploadFile)
	http.HandleFunc("/downloadKey", downloadKey)
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		print("error")
		return
	}
}

func decr(w http.ResponseWriter, req *http.Request) {
	tpl.ExecuteTemplate(w, "decrypt.gohtml", nil)
}

func encr(w http.ResponseWriter, req *http.Request) {
	tpl.ExecuteTemplate(w, "encrypt.gohtml", nil)
}

func downloadKey(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	inkey := req.FormValue("keyString")

	k := struct {
		keyString string
	}{
		keyString: inkey,
	}

	downloadedKey = k.keyString
	var temp []byte

	db(" ", downloadedKey, temp, false)

	tpl.ExecuteTemplate(w, "decrypt.gohtml", nil)
	fmt.Fprintf(w, "Decrypted successfully")
}

func uploadFile(w http.ResponseWriter, req *http.Request) {
	var s string
	if req.Method == "POST" {
		file, fileHeader, err := req.FormFile("upload")
		if err != nil {
			log.Println(err)
			http.Error(w, "Error uploading file", http.StatusInternalServerError)
			return
		}

		defer file.Close()

		bs, err := ioutil.ReadAll(file)
		if err != nil {
			log.Println(err)
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}

		s = string(bs)

		fileName, err := os.Create("./" + fileHeader.Filename)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer fileName.Close()

		_, err = fileName.WriteString(s)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = fileName.Close()
		if err != nil {
			fmt.Println(err)
			return
		}

		key := []byte(keyPattern)

		userKey = EncryptFile(key, fileName.Name())

	}
	tpl.ExecuteTemplate(w, "encrypt.gohtml", nil)
	fmt.Fprintf(w, "User key: "+userKey)
}

func EncryptFile(key []byte, fileName string) string {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, file, nil)

	err = ioutil.WriteFile(encryptedFileName, ciphertext, 0777)
	if err != nil {
		log.Panic(err)
	}

	bitSize := 12

	// Generate RSA key.
	key2, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(key2),
		},
	)

	userKey := clearKey(keyPEM)

	fmt.Println("User Key =" + userKey)

	fmt.Println("File Encrypted successfully!")

	db(fileName, userKey, key, true)

	return userKey
}

//user/file key
func DecryptFile(key []byte, fileName string) {
	ciphertext, err := ioutil.ReadFile(encryptedFileName)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	file, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Panic(err)
	}

	temp := strings.Split(fileName, ".")

	extension := len(temp[1])

	fileFormat := fileName[len(fileName)-extension:]

	fileFormat = "(" + trimLeftChars(fileName, 2) + ")" + fileFormat

	err = ioutil.WriteFile(decryptedFileName+fileFormat, file, 0777)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("File Decrypted Successfully!")
}

func db(file_name string, user_key string, file_key []byte, isEncrypt bool) {
	var UID int

	db, err := sql.Open("mysql", "root:demo1234@tcp(127.0.0.1:3306)/myphp")

	if err != nil {
		panic(err.Error())
	}

	_, err = db.Query("SELECT * FROM encryptedfiles")

	checkErr(err)

	if isEncrypt == true {
		sql := "INSERT INTO encryptedfiles(file_name,file_key,user_key) VALUES (?,?,?)"
		_, err = db.Exec(sql, file_name, file_key, user_key)

		if err != nil {
			panic(err.Error())
		}
	} else {
		res, err := db.Query("SELECT * FROM encryptedfiles WHERE user_key = ?", user_key)
		defer res.Close()

		if err != nil {
			log.Fatal(err)
		}

		if res.Next() {

			err := res.Scan(&UID, &file_name, &file_key, &user_key)

			DecryptFile(file_key, file_name)

			// Delete
			_, err = db.Exec("DELETE FROM encryptedfiles WHERE user_key = ?", user_key)
			if err != nil {
				panic(err)
			}

			if err != nil {
				log.Fatal(err)
			}

		}
	}

	defer db.Close()
}

func clearKey(keyPEM []byte) string {
	tempKey := string(keyPEM)

	tempKey = strings.Replace(tempKey, "-", "", -1)

	tempKey = strings.Replace(tempKey, "BEGIN", "", -1)

	tempKey = strings.Replace(tempKey, "END", "", -1)

	tempKey = strings.Replace(tempKey, "\n", "", -1)

	tempKey = strings.Replace(tempKey, "\n", "", -1)

	tempKey = strings.Replace(tempKey, " ", "", -1)

	//tempKey = strings.ReplaceAll(tempKey, "\n", "")

	return tempKey
}

func init() {
	tpl = template.Must(template.ParseGlob("template/*.gohtml"))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func trimLeftChars(s string, n int) string {
	m := 0
	for i := range s {
		if m >= n {
			return s[i:]
		}
		m++
	}
	return s[:0]
}
