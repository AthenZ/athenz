package main

import (
	"context"
	"fmt"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts/tenant/clients"
)

func main() {
	pem := "<path to client certificate>"
	pk := "<path to private key>"
	ctx := context.Background()
	c, cancel := clients.NewRoleTokenClientSetCacheUpdateDuration(ctx, "https://athenz.io", pem, pk, 3*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ {
		rt, err := c.GetToken("user.provider.domain", []string{""})
		if err != nil {
			fmt.Printf("Error getting role token: %v\n", err)
		} else {
			fmt.Printf("Role token: %s\n", rt.Token)
		}
		time.Sleep(1 * time.Second)
	}

}
