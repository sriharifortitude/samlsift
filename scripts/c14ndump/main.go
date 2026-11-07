// Command c14ndump canonicalizes a document or one element of it, for comparing with other
// implementations (scripts/compare_c14n.py). It is a test tool, not part of samlsift.
//
//	c14ndump FILE exc|inc comments|nocomments [ID|-] [PREFIX,...]
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sriharifortitude/samlsift/internal/c14n"
	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: c14ndump FILE exc|inc comments|nocomments [ID|-] [PREFIX,...]")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	doc, err := xmltree.Parse(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	opt := c14n.Options{Exclusive: os.Args[2] == "exc", WithComments: os.Args[3] == "comments"}
	if len(os.Args) > 5 && os.Args[5] != "" {
		opt.InclusivePrefixes = strings.Split(os.Args[5], ",")
	}
	if len(os.Args) < 5 || os.Args[4] == "-" {
		os.Stdout.Write(c14n.Document(doc, nil, opt))
		return
	}
	var target *xmltree.Node
	doc.Root.Walk(func(n *xmltree.Node) bool {
		if v, ok := n.Attr("", "id"); ok && v == os.Args[4] {
			target = n
		}
		return true
	})
	if target == nil {
		fmt.Fprintln(os.Stderr, "no element with that id")
		os.Exit(2)
	}
	os.Stdout.Write(c14n.Subtree(target, nil, opt))
}
