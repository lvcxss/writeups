package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Im using this function to extract the specific tokens in packets with:
// dst port 8080
// have length (280)
// the token is after 'hotel_sess_state='
func extractFilteredTokens() []string {
	tokens := []string{}
	handle, err := pcap.OpenOffline("traffic.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	re := regexp.MustCompile(`hotel_sess_state=([^&\r\n\s]+)`)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for packet := range packets {
		if packet.Metadata().Length != 280 {
			continue
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		port := layers.TCPPort(8080)
		if tcp.DstPort == port {
			payloadBytes := tcp.LayerPayload()
			if len(payloadBytes) == 0 {
				continue
			}
			payload := string(payloadBytes)
			if matches := re.FindStringSubmatch(payload); len(matches) > 1 {
				tokens = append(tokens, matches[1])
			}
		}

	}
	return tokens
}

func getKey() string {
	p1 := "H0t3lSt@ff0Nly"
	p2 := "K3epS3cr3t!"
	return p1 + p2
}

func xor(data, key []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(key)
	for i, b := range data {
		result[i] = b ^ key[i%keyLen]
	}
	return result
}

func decryptTokens(tokens []string) string {
	result := ""
	for _, token := range tokens {
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return ""
		}
		keyBytes := []byte(getKey())
		xored := xor(decoded, keyBytes)
		result += string(xored)
	}
	return result
}

func main() {
	tokens := extractFilteredTokens()
	fmt.Println("Extracted Tokens: ", len(tokens))
	dec := decryptTokens(tokens)
	fmt.Println("Decrypted Tokens: ", dec)
}
