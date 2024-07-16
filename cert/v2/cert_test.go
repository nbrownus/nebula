package v2

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func BenchmarkCertificate_Marshal(b *testing.B) {
	d := Details{
		Name: "nas2",
		Ips: []netip.Addr{
			netip.MustParseAddr("192.168.5.1"),
		},
		Subnets: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
		},
		Groups: []string{
			"default",
			"syncthing",
		},
		NotBefore: time.Unix(1707416815, 0),
		NotAfter:  time.Unix(1743442015, 0),
		Issuer:    "7eced9f5e1c0503e52d7811937ad1dd2ec70a07f7bb6c4d321d195a8736ef5e3",
		Curve:     0,
	}

	bt, err := d.Marshal()
	assert.NoError(b, err)

	b.Run("details", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = d.Marshal()
		}
	})

	k, _ := hex.DecodeString("68615a67fdf304812a3bb1662726d766aa5fb8700295f80e34a473e6d26d404e")
	s, _ := hex.DecodeString("c3625638efe1f3066703e81b0439b767151850420385ffc172a0846920fd5ea00cdbadf4fc225fcda5c36954960c0532c2870046a6c4523c2a7b41894c59f305")
	c := Certificate{
		Details:   bt,
		PublicKey: k,
		Signature: s,
	}

	b.Run("cert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = c.Marshal()
		}
	})
}

func TestCertificate_Marshal(t *testing.T) {
	d := Details{
		Name: "nas2",
		Ips: []netip.Addr{
			netip.MustParseAddr("192.168.5.1"),
		},
		Subnets: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
		},
		Groups: []string{
			"default",
			"syncthing",
		},
		NotBefore: time.Unix(1707416815, 0),
		NotAfter:  time.Unix(1743442015, 0),
		Issuer:    "7eced9f5e1c0503e52d7811937ad1dd2ec70a07f7bb6c4d321d195a8736ef5e3",
		Curve:     0,
	}

	b, err := d.Marshal()
	assert.NoError(t, err)

	fmt.Println("-- hex details")
	fmt.Println(hex.EncodeToString(b))
	fmt.Println("-- base64 details")
	fmt.Println(base64.StdEncoding.EncodeToString(b))

	k, _ := hex.DecodeString("68615a67fdf304812a3bb1662726d766aa5fb8700295f80e34a473e6d26d404e")
	s, _ := hex.DecodeString("c3625638efe1f3066703e81b0439b767151850420385ffc172a0846920fd5ea00cdbadf4fc225fcda5c36954960c0532c2870046a6c4523c2a7b41894c59f305")
	c := Certificate{
		Details:   b,
		PublicKey: k,
		Signature: s,
	}

	//CnoKBG5hczISCoGKoIUMgPj//w8aAgAAIgdkZWZhdWx0IglzeW5jdGhpbmco77mUrgYw79upvwY6IGhhWmf98wSBKjuxZicm12aqX7hwApX4DjSkc+bSbUBOSiB+ztn14cBQPlLXgRk3rR3S7HCgf3u2xNMh0ZWoc2714xJAw2JWOO/h8wZnA+gbBDm3ZxUYUEIDhf/BcqCEaSD9XqAM2630/CJfzaXDaVSWDAUywocARqbEUjwqe0GJTFnzBQ==
	//MIHDgF0wW4AEbmFzMqEGBATAqAUBogcEBQAAAAAAoxQMB2RlZmF1bHQMCXN5bmN0aGluZ4QEZcUc74UEZ+rQX4Ygfs7Z9eHAUD5S14EZN60d0uxwoH97tsTTIdGVqHNu9eOBIGhhWmf98wSBKjuxZicm12aqX7hwApX4DjSkc+bSbUBOgkDDYlY47+HzBmcD6BsEObdnFRhQQgOF/8FyoIRpIP1eoAzbrfT8Il/NpcNpVJYMBTLChwBGpsRSPCp7QYlMWfMF

	b, err = c.Marshal()
	assert.NoError(t, err)
	fmt.Println("-- hex cert")
	fmt.Println(hex.EncodeToString(b))
	fmt.Println("-- base64 cert")
	fmt.Println(base64.StdEncoding.EncodeToString(b))

	//TODO: test not before too big (> uint64)
	//TODO: test not after too big (> uint64)
	rd, err := c.UnmarshalDetails()
	assert.NoError(t, err)
	fmt.Printf("%+v\n", rd)
}

func TestDetails_Marshal(t *testing.T) {
	d := Details{
		Name: "test-cert",
		Ips: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("fdee::1"),
		},
		Subnets: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.0/24"),
			netip.MustParsePrefix("2600::1/64"),
		},
		Groups: []string{
			"endpoint",
			"http-server",
		},
		NotBefore: time.Unix(10, 0),
		NotAfter:  time.Unix(math.MaxInt64, 0),
		Issuer:    "beef", //TODO
		Curve:     0,
	}

	b, err := d.Marshal()
	assert.NoError(t, err)

	fmt.Println(base64.StdEncoding.EncodeToString(b))
}
