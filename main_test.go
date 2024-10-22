package main

import (
	"fmt"
	"testing"
)

func TestInitSeed(t *testing.T) {
	seed := InitSeed()
	fmt.Println(seed)
}
