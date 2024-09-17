package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/google/uuid"
)

func main() {

	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair("/tmp/cert.pem", "/tmp/key.pem")
	if err != nil {
		panic(err)
	}

	// Load CA cert
	caCert, err := os.ReadFile("/tmp/ca.pem")
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	conn, err := tls.Dial("tcp", "localhost:5696", tlsConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	biID := uuid.New()

	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 2,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				UniqueBatchItemID: biID[:],
				Operation:         kmip14.OperationDiscoverVersions,
				RequestPayload: kmip.DiscoverVersionsRequestPayload{
					ProtocolVersion: []kmip.ProtocolVersion{
						{ProtocolVersionMajor: 1, ProtocolVersionMinor: 2},
					},
				},
			},
		},
	}

	req, err := ttlv.Marshal(msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(req)

	_, err = conn.Write(req)
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 5000)
	_, err = bufio.NewReader(conn).Read(buf)
	if err != nil {
		panic(err)
	}

	resp := ttlv.TTLV(buf)
	fmt.Println(resp)

}
