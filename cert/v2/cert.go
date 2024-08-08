package v2

import (
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
	TagCertCurve     = 1 | classContextSpecific
	TagCertPublicKey = 2 | classContextSpecific
	TagCertSignature = 3 | classContextSpecific

	TagDetailsName      = 0 | classContextSpecific
	TagDetailsIps       = 1 | classConstructed | classContextSpecific
	TagDetailsSubnets   = 2 | classConstructed | classContextSpecific
	TagDetailsGroups    = 3 | classConstructed | classContextSpecific
	TagDetailsIsCA      = 4 | classContextSpecific
	TagDetailsNotBefore = 5 | classContextSpecific
	TagDetailsNotAfter  = 6 | classContextSpecific
	TagDetailsIssuer    = 7 | classContextSpecific
)

const (
	// MaxCertificateSize is the maximum length a valid certificate can be
	MaxCertificateSize = 65536

	// MaxNameLength is limited to a maximum realistic DNS domain name to help facilitate DNS systems
	MaxNameLength = 253

	// MaxSubnetLength is the maximum length a subnet value can be.
	// 16 bytes for an ipv6 address + 1 byte for the prefix length
	MaxSubnetLength = 17
)

type Certificate struct {
	// Details contains the entire asn.1 DER encoded Details struct
	// This is to benefit forwards compatibility in signature checking.
	// signature(RawDetails + PublicKey) == Signature
	RawDetails []byte
	Curve      Curve
	PublicKey  []byte
	Signature  []byte

	//TODO: Should we have a reference to the Details struct and hydrate on unmarshal or force the caller to do it?
}

func UnmarshalCertificate(b []byte, skipKey bool) (*Certificate, error) {
	l := len(b)
	if l == 0 || l > MaxCertificateSize {
		return nil, ErrBadFormat
	}

	input := cryptobyte.String(b)
	// Open the envelope
	if !input.ReadASN1(&input, asn1.SEQUENCE) || input.Empty() {
		return nil, ErrBadFormat
	}

	// Grab the cert details, we need to preserve the tag and length
	var rawDetails cryptobyte.String
	if !input.ReadASN1Element(&rawDetails, TagCertDetails) || rawDetails.Empty() {
		return nil, ErrBadFormat
	}

	var curve Curve
	if !input.ReadOptionalASN1Integer(&curve, TagCertCurve, CURVE25519) {
		return nil, ErrBadFormat
	}

	// Maybe grab the public key
	var rawPublicKey cryptobyte.String
	if skipKey {
		// Even if we don't care to read the public key we need to advance past it
		input.SkipASN1(TagCertPublicKey)

	} else {
		// We expect a public key to be present
		if !input.ReadASN1(&rawPublicKey, TagCertPublicKey) || rawPublicKey.Empty() {
			return nil, ErrBadFormat
		}
	}

	// Grab the signature
	var rawSignature cryptobyte.String
	if !input.ReadASN1(&rawSignature, TagCertSignature) || rawSignature.Empty() {
		return nil, ErrBadFormat
	}

	return &Certificate{
		RawDetails: rawDetails,
		Curve:      curve,
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
	IsCA      bool
	NotBefore time.Time
	NotAfter  time.Time
	Issuer    []byte
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

	// Read the ip addresses
	var subString cryptobyte.String
	if !b.ReadASN1(&subString, TagDetailsIps) || subString.Empty() {
		return nil, ErrBadFormat
	}

	var ips []netip.Addr
	var val cryptobyte.String
	for !subString.Empty() {
		if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() {
			return nil, ErrBadFormat
		}

		ip, ok := netip.AddrFromSlice(val)
		if !ok {
			return nil, ErrBadFormat
		}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		// We had the ips field present but no ips were found
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
			if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxSubnetLength {
				return nil, ErrBadFormat
			}

			var subnet netip.Prefix
			if err := subnet.UnmarshalBinary(val); err != nil {
				return nil, ErrBadFormat
			}
			subnets = append(subnets, subnet)
		}

		if len(subnets) == 0 {
			// We had the subnets field present but no subnets were found
			return nil, ErrBadFormat
		}
	}

	// Read out any groups
	if !b.ReadOptionalASN1(&subString, &found, TagDetailsGroups) {
		return nil, ErrBadFormat
	}

	var groups []string
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.UTF8String) || val.Empty() {
				return nil, ErrBadFormat
			}
			groups = append(groups, string(val))
		}

		if len(groups) == 0 {
			// We had the groups field present but no groups were found
			return nil, ErrBadFormat
		}
	}

	// Read out IsCA
	var isCa bool
	if !b.ReadOptionalASN1Boolean(&isCa, TagDetailsIsCA, false) {
		return nil, ErrBadFormat
	}

	// Read not before and not after
	var notBefore int64
	if !b.ReadASN1Int64WithTag(&notBefore, TagDetailsNotBefore) {
		return nil, ErrBadFormat
	}

	var notAfter int64
	if !b.ReadASN1Int64WithTag(&notAfter, TagDetailsNotAfter) {
		return nil, ErrBadFormat
	}

	// Read issuer
	var issuer cryptobyte.String
	if !b.ReadASN1(&issuer, TagDetailsIssuer) || issuer.Empty() {
		return nil, ErrBadFormat
	}

	return &Details{
		Name:      string(name),
		Ips:       ips,
		Subnets:   subnets,
		Groups:    groups,
		NotBefore: time.Unix(notBefore, 0),
		NotAfter:  time.Unix(notAfter, 0),
		Issuer:    issuer,
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

		// Add the ips
		if len(d.Ips) == 0 {
			//TODO: this is an error
			//TODO: in general do we want to refuse to marshal an invalid certificate?
		}

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

		// Add IsCA only if true
		if d.IsCA {
			b.AddASN1(TagDetailsIsCA, func(b *cryptobyte.Builder) {
				b.AddUint8(0xff)
			})
		}

		// Add not before
		b.AddASN1Int64WithTag(d.NotBefore.Unix(), TagDetailsNotBefore)

		// Add not after
		b.AddASN1Int64WithTag(d.NotAfter.Unix(), TagDetailsNotAfter)

		// Add the issuer
		b.AddASN1(TagDetailsIssuer, func(b *cryptobyte.Builder) {
			b.AddBytes(d.Issuer)
		})
	})

	if err != nil {
		return nil, err
	}

	return b.Bytes()
}
