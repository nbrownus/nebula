package cidr

import (
	"fmt"
	"net"

	"github.com/slackhq/nebula/iputil"
)

type Node struct {
	left   *Node
	right  *Node
	parent *Node
	Value  interface{}
}

type entry struct {
	CIDR  *net.IPNet
	Value *interface{}
}

type Tree4 struct {
	root *Node
	list []entry
}

const (
	startbit = iputil.VpnIp(0x80000000)
)

func NewTree4() *Tree4 {
	tree := new(Tree4)
	tree.root = &Node{}
	tree.list = make([]entry, 0)
	return tree
}

func (tree *Tree4) AddCIDR(cidr *net.IPNet, val interface{}) {
	bit := startbit
	node := tree.root
	next := tree.root

	ip := iputil.Ip2VpnIp(cidr.IP)
	mask := iputil.Ip2VpnIp(cidr.Mask)

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

	// We already have this range so update the value
	if next != nil {
		node.Value = val
		return
	}

	// Build up the rest of the tree we don't already have
	for bit&mask != 0 {
		next = &Node{}
		next.parent = node

		if ip&bit != 0 {
			node.right = next
		} else {
			node.left = next
		}

		bit >>= 1
		node = next
	}

	// Final node marks our cidr, set the value
	node.Value = val
	tree.list = append(tree.list, entry{CIDR: cidr, Value: &node.Value})
}

// Contains finds the first match that contains the provided ip address, which may be the least specific
func (tree *Tree4) Contains(ip iputil.VpnIp) (value interface{}) {
	bit := startbit
	node := tree.root

	for node != nil {
		if node.Value != nil {
			return node.Value
		}

		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1

	}

	return value
}

// MostSpecificContains finds the most specific match that contains the provided ip address
func (tree *Tree4) MostSpecificContains(ip iputil.VpnIp) (value interface{}) {
	bit := startbit
	node := tree.root

	for node != nil {
		if node.Value != nil {
			value = node.Value
		}

		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1
	}

	return value
}

// Match finds an exact ip address, all bits must be present in the tree
func (tree *Tree4) Match(ip iputil.VpnIp) (value interface{}) {
	bit := startbit
	node := tree.root
	lastNode := node

	for node != nil {
		lastNode = node
		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1
	}

	if bit == 0 && lastNode != nil {
		value = lastNode.Value
	}
	return value
}

// List will return all CIDRs and their current values. Do not modify the contents!
func (tree *Tree4) List() []entry {
	return tree.list
}

func (tree *Tree4) Dot() string {
	type thing struct {
		bits int
		ip   int
		n    *Node
	}

	body := ""
	bitranks := [33][]int{}
	q := []*thing{{bits: 0, ip: 0, n: tree.root}}
	i := 0

	for len(q) > 0 {
		c := q[0]

		if c.n != nil {
			if c.n.left != nil || c.n.right != nil {
				body += fmt.Sprintf("\tnode%d -> { node%d node%d }\n", i, i+len(q), i+len(q)+1)
				bits := c.bits + 1
				bit := 1 << (32 - bits)

				q = append(
					q,
					&thing{bits: bits, ip: c.ip, n: c.n.left},
					&thing{bits: bits, ip: c.ip | bit, n: c.n.right},
				)
			}

			if c.n.Value != nil {
				body += fmt.Sprintf("\tnode%d [style=filled,label=\"cidr: %s/%d, value: %v\"]\n", i, iputil.VpnIp(c.ip), c.bits, c.n.Value)
			} else {
				body += fmt.Sprintf("\tnode%d [label=\"cidr: %s/%d\"]\n", i, iputil.VpnIp(c.ip), c.bits)
			}
		} else {
			body += fmt.Sprintf("\tnode%d [label=\"nil\"]\n", i)
		}

		bitranks[c.bits] = append(bitranks[c.bits], i)
		q = q[1:]
		i++
	}

	for i, sub := range bitranks {
		body += fmt.Sprintf("subgraph sub%d {\n\trank=\"same\"\n", i)
		for _, s := range sub {
			body += fmt.Sprintf("\tnode%d\n", s)
		}
		body += "}\n"
	}

	return "digraph {\n\tnode [shape=box]\n" + body + "}\n"
}
