package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/md4"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ripemd160"
)

func hashCompare(providedHash string, hashType string, words []string, wordChannel chan string, errorChannel chan error, wordsChecked *uint64) {
	for _, word := range words {
		hashedWord, err := hash(word, hashType)
		if err != nil {
			errorChannel <- err
		}
		atomic.AddUint64(wordsChecked, 1)
		if hashedWord == providedHash {
			wordChannel <- word
		}
	}
}

func crack(providedHash string, hashType string, wordlist string) (string, uint64, error) {
	f, err := os.Open(wordlist)
	defer f.Close()
	if err != nil {
		return "", 0, err
	}
	buf := bufio.NewReader(f)
	wordChannel := make(chan string)
	errorChannel := make(chan error)
	var wordsChecked uint64
	for {
		block := []string{}
		blockSize := 600000
		for i := 0; i < blockSize; i++ {
			line, _, err := buf.ReadLine()
			if err == io.EOF {
				break
			}
			block = append(block, string(line))
		}
		go hashCompare(providedHash, hashType, block, wordChannel, errorChannel, &wordsChecked)
		select {
		case word := <-wordChannel:
			return word, wordsChecked, nil
		case channelError := <-errorChannel:
			return "", wordsChecked, channelError
		default:
		}
	}
}

func hash(word string, hashType string) (string, error) {
	bytesToHash := []byte(word)
	switch hashType {
	case "MD4":
		h := md4.New()
		io.WriteString(h, word)
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	case "MD5":
		return fmt.Sprintf("%x", md5.Sum(bytesToHash)), nil
	case "SHA-1":
		return fmt.Sprintf("%x", sha1.Sum(bytesToHash)), nil
	case "SHA-224":
		return fmt.Sprintf("%x", sha256.Sum224(bytesToHash)), nil
	case "SHA-256":
		return fmt.Sprintf("%x", sha256.Sum256(bytesToHash)), nil
	case "SHA-384":
		return fmt.Sprintf("%x", sha512.Sum384(bytesToHash)), nil
	case "SHA-512":
		return fmt.Sprintf("%x", sha512.Sum512(bytesToHash)), nil
	case "RIPEMD-160":
		h := ripemd160.New()
		io.WriteString(h, word)
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	}
	return "", fmt.Errorf("%v is not an implemented hashing function.", hashType)
}

func main() {
	hashes := []string{"MD4", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA384", "SHA-512", "RIPEMD-160", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHA512-224", "SHA512-256", "BLAKE2s-256", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512"}
	app := cli.NewApp()
	app.Commands = []*cli.Command{
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "List available hashes",
			Action: func(c *cli.Context) error {
				stringSlices := strings.Join(hashes, "\n")
				fmt.Println(stringSlices)
				return nil
			},
		},
		{
			Name:      "crack",
			Aliases:   []string{"c"},
			Usage:     "Attempt to crack a hash",
			ArgsUsage: "[crack this hash] [of this hash type] [using/this/wordlist]",
			Action: func(c *cli.Context) error {
				startTime := time.Now()
				// if arguments are missing error
				if c.Args().Len() < 3 {
					return fmt.Errorf("%v %v", app.Commands[1].HelpName, app.Commands[1].ArgsUsage)
				}
				providedHash := c.Args().Get(0)
				hashType := c.Args().Get(1)
				wordList := c.Args().Get(2)
				word, wordsChecked, err := crack(providedHash, hashType, wordList)
				if err != nil {
					return err
				}
				fmt.Println(app.Commands[1].HelpName, providedHash, hashType, wordList)
				duration := time.Since(startTime)
				fmt.Printf("Password: %v\n", word)
				fmt.Printf("Words Checked: %v, Elapsed Time: %v\n", wordsChecked, duration)
				return nil
			},
		},
		{
			Name:      "hash",
			Aliases:   []string{"ha"},
			Usage:     "Attempt to hash a string",
			ArgsUsage: "[hash this string] [using this hash type]",
			Action: func(c *cli.Context) error {
				// if arguments are missing error
				if c.Args().Len() < 2 {
					return fmt.Errorf("%v %v", app.Commands[2].HelpName, app.Commands[2].ArgsUsage)
				}
				word := c.Args().Get(0)
				hashType := strings.ToUpper(c.Args().Get(1))
				if word != "" || hashType != "" {
					fmt.Println(app.Commands[1].HelpName, word, hashType)
					hash, err := hash(word, hashType)
					if err != nil {
						return err
					}
					fmt.Println(hash)
				}

				return nil
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
