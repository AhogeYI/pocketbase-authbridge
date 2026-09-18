// Minimal integration example, issuer side: a PocketBase binary where every
// login/refresh additionally mints a service token that standalone services
// verify offline.
//
//	go run ./example serve
package main

import (
	"log"

	authbridge "github.com/Ahogeyi/pocketbase-authbridge"

	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()
	authbridge.Register(app)
	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
