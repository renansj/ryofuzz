package nuclei

import (
	"strings"

	"github.com/antchfx/htmlquery"
)

// xpathExists reports whether an xpath query matches at least one node.
func xpathExists(htmlBody, query string) (bool, error) {
	doc, err := htmlquery.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return false, err
	}
	nodes, err := htmlquery.QueryAll(doc, query)
	if err != nil {
		return false, err
	}
	return len(nodes) > 0, nil
}

// xpathExtract returns the text of all nodes matching the query.
func xpathExtract(htmlBody, query string) ([]string, error) {
	doc, err := htmlquery.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return nil, err
	}
	nodes, err := htmlquery.QueryAll(doc, query)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range nodes {
		out = append(out, htmlquery.InnerText(n))
	}
	return out, nil
}
