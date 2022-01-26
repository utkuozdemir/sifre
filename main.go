package main

import (
	"math/rand"
	"time"

	"github.com/utkuozdemir/sifre/cmd"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	cmd.Execute()
}
