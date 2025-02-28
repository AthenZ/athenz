package main

import (
	"context"
	"fmt"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts/token"
)

func main() {
	pem := "<path to client certificate>"
	pk := "<path to private key>"
	ctx := context.Background()
	c, cancel := token.NewAccessTokenClientSetCacheUpdateDuration(ctx, "https://athenz.io", pem, pk, 3*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ {
		at, err := c.GetToken("user.provider.domain", []string{""})
		if err != nil {
			fmt.Printf("Error getting access token: %v\n", err)
		} else {
			fmt.Printf("AccessToken: %s\n", at.Token)
			fmt.Printf("Expires_in: %d\n", at.ExpiryTime)
		}
		time.Sleep(1 * time.Second)
	}
}
