package suez

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func Encrypt(key string, text string) (string, error) {
	if len(key) == 0 {
		return text, nil
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	b := base64.URLEncoding.EncodeToString([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	bc := base64.URLEncoding.EncodeToString(ciphertext)
	return bc, nil
}

func Decrypt(key, b64text string) (string, error) {
	text, _ := base64.URLEncoding.DecodeString(b64text)
	if len(key) == 0 {
		return string(text), nil
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	if len(text) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.URLEncoding.DecodeString(string(text))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func MakeCookie(key string, value string, days int) *http.Cookie {
	// log.Printf("Making cookie %s with value %s for %d days\n", key, value, days)
	expiration := time.Now().AddDate(0, 0, days)

	return &http.Cookie{
		Name:    key,
		Value:   value,
		Expires: expiration,
		Path:    "/",
	}
}

func GenRandomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func OptionsFromQuery(hostItem HostConfigItem, values url.Values) []oauth2.AuthCodeOption {
	options := []oauth2.AuthCodeOption{}

	if values.Get("force") == "1" {
		options = append(options, oauth2.ApprovalForce)
	}

	if values.Get("offline") == "1" {
		options = append(options, oauth2.AccessTypeOffline)
	}

	// Since oauth2.AccessTypeOnline is default, we'll just leave.

	for _, row := range hostItem.Authentication.AddValues {
		options = append(options, oauth2.SetAuthURLParam(row[0], row[1]))
	}

	return options
}

func HtmlRedirect(url string) string {
	return fmt.Sprintf("<html><meta http-equiv=\"refresh\" content=\"0;url='%s'\" /></html>", url)
}

type User struct {
	Email string `json:"email"`
}

func GetIdentityWithClient(url string, post bool, client *http.Client) (string, error) {
	var email *http.Response
	var err error

	if post {
		email, err = client.Post(url, "", nil)
	} else {
		email, err = client.Get(url)
	}

	if err != nil {
		return "", err
	}

	defer email.Body.Close()

	data, _ := ioutil.ReadAll(email.Body)

	var user User
	err = json.Unmarshal(data, &user)

	if err != nil {
		return "", err
	}

	return user.Email, nil
}

func HasPrefixFromList(s string, prefixList []string) bool {
	for _, item := range prefixList {
		if strings.HasPrefix(s, item) {
			return true
		}
	}
	return false
}
