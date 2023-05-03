package main

import (
	"fmt"
	"github.com/unsafesystems/opinionated"
	"net"
)

func main() {
	server, err := opinionated.NewServer(
		opinionated.WithInsecureHealth(),
		opinionated.WithEmbeddedMetricsEndpoint(),
	)
	if err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", 8443))
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on", l.Addr().String())

	err = server.Serve(l)
	if err != nil {
		panic(err)
	}
}
