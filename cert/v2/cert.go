package v2

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	classConstructed     = 0x20
	classContextSpecific = 0x80

	TagCertDetails   = 0 | classConstructed | classContextSpecific
	TagCertPublicKey = 1 | classContextSpecific
	TagCertSignature = 2 | classContextSpecific

	TagDetailsName      = 0 | classContextSpecific
	TagDetailsIps       = 1 | classConstructed | classContextSpecific
	TagDetailsSubnets   = 2 | classConstructed | classContextSpecific
	TagDetailsGroups    = 3 | classConstructed | classContextSpecific
	TagDetailsNotBefore = 4 | classContextSpecific
	TagDetailsNotAfter  = 5 | classContextSpecific
	TagDetailsIssuer    = 6 | classContextSpecific
)

const (
	MaxPublicKeyLength = 32 //TODO: P256 is bigger

	// MaxNameLength is the maximum length a name can be
	// The limit comes from rfc1035 defining a label can not exceed 63 octets
	//TODO: 63 assumes names dont contain `.`. 253 would be the maximum but then we may want to inspect the name further
	// to ensure it is fully compatible with dns (punycode)
	MaxNameLength = 63

	// MaxAddrLength is the maximum length of an ip address
	// 16 bytes for an ipv6 address
	MaxAddrLength = 16

	// MaxSubnetLength is the maximum length a subnet value can be.
	// 16 bytes for an ipv6 address + 1 byte for the prefix length
	MaxSubnetLength = MaxAddrLength + 1

	// MaxAddresses is the maximum number of ip addresses allowed in a certificate
	//TODO: If 2 is the number then its better to have discrete fields in asn1
	// 2 would be to support a single v4 and v6 address per host
	MaxAddresses = 2

	// MaxSubnets is the maximum number of subnets allowed in a certificate
	MaxSubnets = 1024

	// MaxGroups is the maximum number of groups allowed in a certificate
	MaxGroups = 1024

	// MaxGroupLength is the maximum length of any given group
	//TODO: we may want to follow dns limits here as well
	MaxGroupLength = 1024

	//TODO: other fields still need a max value
)

type Certificate struct {
	// Details contains the entire asn.1 DER encoded Details struct
	// This is to benefit forwards compatibility in signature checking.
	// signature(RawDetails + PublicKey) == Signature
	RawDetails []byte
	PublicKey  []byte
	Signature  []byte

	//TODO: Should we have a reference to the Details struct and hydrate on unmarshal or force the caller to do it?
}

func UnmarshalCertificate(b []byte, skipKey bool) (*Certificate, error) {
	input := cryptobyte.String(b)
	if len(input) == 0 {
		return nil, ErrBadFormat
	}

	// Open the envelope
	if !input.ReadASN1(&input, asn1.SEQUENCE) || input.Empty() {
		return nil, ErrBadFormat
	}

	// Grab the cert details, we need to preserve the tag and length
	var rawDetails cryptobyte.String
	if !input.ReadASN1Element(&rawDetails, TagCertDetails) || rawDetails.Empty() {
		return nil, ErrBadFormat
	}

	// Maybe grab the public key
	var rawPublicKey cryptobyte.String
	if skipKey {
		// Even if we don't care to read the public key we need to advance past it
		input.SkipASN1(TagCertPublicKey)

	} else {
		// We expect a public key to be present
		//TODO: check length, this also doesnt work as expected ith the skipKey
		if !input.ReadASN1(&rawPublicKey, TagCertPublicKey) || rawPublicKey.Empty() {
			return nil, ErrBadFormat
		}
	}

	// Grab the signature
	var rawSignature cryptobyte.String
	//TODO: check length
	if !input.ReadASN1(&rawSignature, TagCertSignature) || rawSignature.Empty() {
		return nil, ErrBadFormat
	}

	return &Certificate{
		RawDetails: rawDetails,
		PublicKey:  rawPublicKey,
		Signature:  rawSignature,
	}, nil
}

func UnmarshalCertificateWithPublicKey(b []byte, publicKey []byte) (*Certificate, error) {
	//TODO: remove skipKey from UnmarshalCertificate
	panic("asdfasdf")
}

func (c *Certificate) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	// Outermost certificate
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		// Add the cert details which is already marshalled
		b.AddBytes(c.RawDetails)

		// Add the public key
		b.AddASN1(TagCertPublicKey, func(b *cryptobyte.Builder) {
			b.AddBytes(c.PublicKey)
		})

		// Add the signature
		b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
			b.AddBytes(c.Signature)
		})
	})

	return b.Bytes()
}

func (c *Certificate) UnmarshalDetails() (*Details, error) {
	return unmarshalDetails(c.RawDetails)
}

type Details struct {
	Name      string
	Ips       []netip.Addr
	Subnets   []netip.Prefix
	Groups    []string
	NotBefore time.Time
	NotAfter  time.Time
	Issuer    string
	//TODO: Curve would be better as a property of the public key but noise would get upset since the key length would
	// be longer than expected. If we want to do any sanity checking on the public key matching the curve then we have
	// to unmarshal the details before we can accomplish that
	Curve Curve
}

func unmarshalDetails(b cryptobyte.String) (*Details, error) {
	// Open the envelope
	if !b.ReadASN1(&b, asn1.SEQUENCE) || b.Empty() {
		return nil, ErrBadFormat
	}

	// Read the name
	var name cryptobyte.String
	if !b.ReadASN1(&name, TagDetailsName) || name.Empty() || len(name) > MaxNameLength {
		return nil, ErrBadFormat
	}

	// Read the ips
	var subString cryptobyte.String
	if !b.ReadASN1(&subString, TagDetailsIps) || subString.Empty() {
		return nil, ErrBadFormat
	}

	var ips []netip.Addr
	var val cryptobyte.String
	for !subString.Empty() {
		if len(ips) == MaxAddresses {
			// There are still bytes left to process and we are at max
			return nil, ErrBadFormat
		}

		if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxAddrLength {
			return nil, ErrBadFormat
		}

		ip, ok := netip.AddrFromSlice(val)
		if !ok {
			return nil, ErrBadFormat
		}
		ips = append(ips, ip)
	}

	// Make sure we have at least 1 ip address
	if len(ips) < 1 {
		return nil, ErrBadFormat
	}

	// Read out any subnets
	var found bool
	if !b.ReadOptionalASN1(&subString, &found, TagDetailsSubnets) {
		return nil, ErrBadFormat
	}

	var subnets []netip.Prefix
	if found {
		for !subString.Empty() {
			if len(subnets) == MaxSubnets {
				// There are still bytes left to process and we are at max
				return nil, ErrBadFormat
			}

			if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxSubnetLength {
				return nil, ErrBadFormat
			}

			var subnet netip.Prefix
			if err := subnet.UnmarshalBinary(val); err != nil {
				return nil, ErrBadFormat
			}
			subnets = append(subnets, subnet)
		}
	}

	// Read out any groups
	if !b.ReadOptionalASN1(&subString, &found, TagDetailsGroups) {
		return nil, ErrBadFormat
	}

	var groups []string
	if found {
		for !subString.Empty() {
			if len(groups) == MaxSubnets {
				// There are still bytes left to process and we are at max
				return nil, ErrBadFormat
			}

			if !subString.ReadASN1(&val, asn1.UTF8String) || val.Empty() || len(val) > MaxGroupLength {
				return nil, ErrBadFormat
			}
			groups = append(groups, string(val))
		}
	}

	// Read not before and not after
	//TODO: enforce limits
	var notBefore int64
	if !b.ReadASN1Int64WithTag(&notBefore, TagDetailsNotBefore) {
		return nil, ErrBadFormat
	}

	//TODO: enforce limits
	var notAfter int64
	if !b.ReadASN1Int64WithTag(&notAfter, TagDetailsNotAfter) {
		return nil, ErrBadFormat
	}

	// Read issuer
	//TODO: enforce limits
	var issuer cryptobyte.String
	if !b.ReadASN1(&issuer, TagDetailsIssuer) || issuer.Empty() {
		return nil, ErrBadFormat
	}

	//TODO: curve and enforce limits

	return &Details{
		Name:      string(name),
		Ips:       ips,
		Subnets:   subnets,
		Groups:    groups,
		NotBefore: time.Unix(notBefore, 0),
		NotAfter:  time.Unix(notAfter, 0),
		Issuer:    hex.EncodeToString(issuer),
		Curve:     CURVE25519, //TODO
	}, nil
}

func (d *Details) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	var err error

	// Details are a structure
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		// Add the name
		b.AddASN1(TagDetailsName, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(d.Name))
		})

		// Add the ips if any exist
		if len(d.Ips) > 0 {
			b.AddASN1(TagDetailsIps, func(b *cryptobyte.Builder) {
				for _, subnet := range d.Ips {
					sb, innerErr := subnet.MarshalBinary()
					if innerErr != nil {
						// MarshalBinary never returns an error
						err = fmt.Errorf("unable to marshal ip: %w", err)
						return
					}
					b.AddASN1OctetString(sb)
				}
			})
		}

		// Add the subnets if any exist
		if len(d.Subnets) > 0 {
			b.AddASN1(TagDetailsSubnets, func(b *cryptobyte.Builder) {
				for _, subnet := range d.Subnets {
					sb, innerErr := subnet.MarshalBinary()
					if innerErr != nil {
						// MarshalBinary never returns an error
						err = fmt.Errorf("unable to marshal subnet: %w", err)
						return
					}
					b.AddASN1OctetString(sb)
				}
			})
		}

		// Add groups if any exist
		if len(d.Groups) > 0 {
			b.AddASN1(TagDetailsGroups, func(b *cryptobyte.Builder) {
				for _, group := range d.Groups {
					b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(group))
					})
				}
			})
		}

		// Add not before
		b.AddASN1Int64WithTag(d.NotBefore.Unix(), TagDetailsNotBefore)

		// Add not after
		b.AddASN1Int64WithTag(d.NotAfter.Unix(), TagDetailsNotAfter)

		// Add the issuer
		var h []byte
		h, err = hex.DecodeString(d.Issuer) //TODO: there is probably a better way to avoid building this intermediate slice
		if err != nil {
			//TODO: might want to wrap this
			return
		}
		b.AddASN1(TagDetailsIssuer, func(b *cryptobyte.Builder) {
			b.AddBytes(h)
		})

		//TODO: Curve
	})

	if err != nil {
		return nil, err
	}

	return b.Bytes()
}
