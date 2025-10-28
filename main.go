package main

import (
	"context"
	"log"

	"github.com/bnb-chain/tss-lib/v2/eddsa/signing"
)

func main() {
	ctx := context.Background()
	err := signing.RunTSSAndSubmit(ctx, "Ac4R6EFdjkNaVBoUk4T26XrGmdhQTdHcwpswCqopfbS6")
	if err != nil {
		log.Fatalf("failed to run TSS and submit: %v", err)
	}
}
