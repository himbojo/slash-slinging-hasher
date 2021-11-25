package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/md4"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ripemd160"
)

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
				// if arguments are missing error
				if c.Args().Len() < 3 {
					return fmt.Errorf("%v %v", app.Commands[1].HelpName, app.Commands[1].ArgsUsage)
				}
				hash := strings.ToUpper(c.Args().Get(0))
				hashType := c.Args().Get(1)
				wordList := c.Args().Get(2)
				fmt.Println(app.Commands[1].HelpName, hash, hashType, wordList)
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
				stringToHash := c.Args().Get(0)
				bytesToHash := []byte(stringToHash)
				hashType := strings.ToUpper(c.Args().Get(1))
				fmt.Println(app.Commands[1].HelpName, stringToHash, hashType)
				switch hashType {
				case "MD4":
					h := md4.New()
					io.WriteString(h, stringToHash)
					fmt.Printf("%x\n", h.Sum(nil))
				case "MD5":
					fmt.Printf("%x\n", md5.Sum(bytesToHash))
				case "SHA-1":
					fmt.Printf("%x\n", sha1.Sum(bytesToHash))
				case "SHA-224":
					fmt.Printf("%x\n", sha256.Sum224(bytesToHash))
				case "SHA-256":
					fmt.Printf("%x\n", sha256.Sum256(bytesToHash))
				case "SHA-384":
					fmt.Printf("%x\n", sha512.Sum384(bytesToHash))
				case "SHA-512":
					fmt.Printf("%x\n", sha512.Sum512(bytesToHash))
				case "RIPEMD-160":
					h := ripemd160.New()
					io.WriteString(h, stringToHash)
					fmt.Printf("%x\n", h.Sum(nil))
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
