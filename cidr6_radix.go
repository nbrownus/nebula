package nebula

import (
	"encoding/binary"
	"net"
)

type CIDR6Tree struct {
	root4 *CIDRNode
	root6 *CIDRNode
}

func NewCIDR6Tree() *CIDR6Tree {
	tree := new(CIDR6Tree)
	tree.root4 = &CIDRNode{}
	tree.root6 = &CIDRNode{}
	return tree
}

func (tree *CIDR6Tree) AddCIDR(cidr *net.IPNet, val interface{}) {
	var node, next *CIDRNode

	cidrIP := cidr.IP.To4()
	if cidrIP != nil {
		node = tree.root4
		next = tree.root4

	} else {
		cidrIP = cidr.IP
		node = tree.root6
		next = tree.root6
	}

	for i := 0; i < len(cidrIP); i += 4 {
		ip := binary.BigEndian.Uint32(cidrIP[i : i+4])
		mask := binary.BigEndian.Uint32(cidr.Mask[i : i+4])
		bit := startbit

		// Find our last ancestor in the tree
		for bit&mask != 0 {
			if ip&bit != 0 {
				next = node.right
			} else {
				next = node.left
			}

			if next == nil {
				break
			}

			bit = bit >> 1
			node = next
		}

		// Build up the rest of the tree we don't already have
		for bit&mask != 0 {
			next = &CIDRNode{}
			next.parent = node

			if ip&bit != 0 {
				node.right = next
			} else {
				node.left = next
			}

			bit >>= 1
			node = next
		}
	}

	// Final node marks our cidr, set the value
	node.value = val
}

// Finds the first match, which may be the least specific
func (tree *CIDR6Tree) Contains(ip IP) (value interface{}) {
	var node *CIDRNode

	wholeIP, isV4 := ip.ToV4()
	if isV4 {
		node = tree.root4
	} else {
		node = tree.root6
	}

	for i := 0; i < len(wholeIP); i += 4 {
		ip := ip2int(wholeIP[i : i+4])
		bit := startbit

		for node != nil {
			if node.value != nil {
				return node.value
			}

			// Check if we have reached the end and the above return did not trigger, move to the next uint32 if available
			if bit == 0 {
				break
			}

			if ip&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}

			bit >>= 1
		}
	}

	// Nothing found
	return
}

// Finds the most specific match
func (tree *CIDR6Tree) MostSpecificContains(ip IP) (value interface{}) {
	var node *CIDRNode

	wholeIP, isV4 := ip.ToV4()
	if isV4 {
		node = tree.root4
	} else {
		node = tree.root6
	}

	for i := 0; i < len(wholeIP); i += 4 {
		ip := ip2int(wholeIP[i : i+4])
		bit := startbit

		for node != nil {
			if node.value != nil {
				value = node.value
			}

			if bit == 0 {
				break
			}

			if ip&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}

			bit >>= 1
		}
	}

	return value
}

// Finds the most specific match
func (tree *CIDR6Tree) Match(ip IP) (value interface{}) {
	var node *CIDRNode
	var bit uint32

	wholeIP, isV4 := ip.ToV4()
	if isV4 {
		node = tree.root4
	} else {
		node = tree.root6
	}

	for i := 0; i < len(wholeIP); i += 4 {
		ip := ip2int(wholeIP[i : i+4])
		bit = startbit

		for node != nil && bit > 0 {
			if ip&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}

			bit >>= 1
		}
	}

	if bit == 0 && node != nil {
		value = node.value
	}

	return value
}
