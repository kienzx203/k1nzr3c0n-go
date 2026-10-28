package graph

import (
	"bytes"
	"encoding/xml"
	"strconv"
)

// ── GraphML (yEd / Gephi / Cytoscape) ──────────────────────────────────────

type gmlData struct {
	Key string `xml:"key,attr"`
	Val string `xml:",chardata"`
}
type gmlNode struct {
	ID   string    `xml:"id,attr"`
	Data []gmlData `xml:"data"`
}
type gmlEdge struct {
	ID     string    `xml:"id,attr"`
	Source string    `xml:"source,attr"`
	Target string    `xml:"target,attr"`
	Data   []gmlData `xml:"data"`
}

// ExportGraphML renders the whole graph as GraphML for desktop graph tools.
func (g *Graph) ExportGraphML() []byte {
	type key struct {
		ID   string `xml:"id,attr"`
		For  string `xml:"for,attr"`
		Name string `xml:"attr.name,attr"`
		Type string `xml:"attr.type,attr"`
	}
	type graphBody struct {
		EdgeDefault string    `xml:"edgedefault,attr"`
		Nodes       []gmlNode `xml:"node"`
		Edges       []gmlEdge `xml:"edge"`
	}
	type graphml struct {
		XMLName xml.Name  `xml:"graphml"`
		Xmlns   string    `xml:"xmlns,attr"`
		Keys    []key     `xml:"key"`
		Graph   graphBody `xml:"graph"`
	}
	doc := graphml{
		Xmlns: "http://graphml.graphdrawing.org/xmlns",
		Keys: []key{
			{"label", "node", "label", "string"},
			{"group", "node", "group", "string"},
			{"risk", "node", "risk", "int"},
			{"internal", "node", "internal", "boolean"},
			{"title", "node", "title", "string"},
			{"elabel", "edge", "label", "string"},
		},
		Graph: graphBody{EdgeDefault: "directed"},
	}
	for id, n := range g.Nodes {
		doc.Graph.Nodes = append(doc.Graph.Nodes, gmlNode{ID: id, Data: []gmlData{
			{"label", n.Label}, {"group", n.Group}, {"risk", strconv.Itoa(n.Risk)},
			{"internal", strconv.FormatBool(n.Internal)}, {"title", n.Title},
		}})
	}
	for i, e := range g.Edges {
		doc.Graph.Edges = append(doc.Graph.Edges, gmlEdge{
			ID: "e" + strconv.Itoa(i), Source: e.From, Target: e.To,
			Data: []gmlData{{"elabel", e.Label}},
		})
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	_ = enc.Encode(doc)
	return buf.Bytes()
}

// ── GEXF (Gephi native) ─────────────────────────────────────────────────────

// ExportGEXF renders the whole graph as GEXF 1.2 for Gephi.
func (g *Graph) ExportGEXF() []byte {
	type attvalue struct {
		For string `xml:"for,attr"`
		Val string `xml:"value,attr"`
	}
	type gxNode struct {
		ID        string     `xml:"id,attr"`
		Label     string     `xml:"label,attr"`
		AttValues []attvalue `xml:"attvalues>attvalue"`
	}
	type gxEdge struct {
		ID     string `xml:"id,attr"`
		Source string `xml:"source,attr"`
		Target string `xml:"target,attr"`
		Label  string `xml:"label,attr,omitempty"`
	}
	type attribute struct {
		ID    string `xml:"id,attr"`
		Title string `xml:"title,attr"`
		Type  string `xml:"type,attr"`
	}
	type gexf struct {
		XMLName xml.Name `xml:"gexf"`
		Xmlns   string   `xml:"xmlns,attr"`
		Version string   `xml:"version,attr"`
		Graph   struct {
			Mode            string      `xml:"mode,attr"`
			DefaultEdgeType string      `xml:"defaultedgetype,attr"`
			Attributes      struct {
				Class string      `xml:"class,attr"`
				Attrs []attribute `xml:"attribute"`
			} `xml:"attributes"`
			Nodes []gxNode `xml:"nodes>node"`
			Edges []gxEdge `xml:"edges>edge"`
		} `xml:"graph"`
	}
	var doc gexf
	doc.Xmlns = "http://gexf.net/1.2"
	doc.Version = "1.2"
	doc.Graph.Mode = "static"
	doc.Graph.DefaultEdgeType = "directed"
	doc.Graph.Attributes.Class = "node"
	doc.Graph.Attributes.Attrs = []attribute{
		{"group", "group", "string"}, {"risk", "risk", "integer"}, {"internal", "internal", "boolean"},
	}
	for id, n := range g.Nodes {
		label := n.Label
		if label == "" {
			label = id
		}
		doc.Graph.Nodes = append(doc.Graph.Nodes, gxNode{ID: id, Label: label, AttValues: []attvalue{
			{"group", n.Group}, {"risk", strconv.Itoa(n.Risk)}, {"internal", strconv.FormatBool(n.Internal)},
		}})
	}
	for i, e := range g.Edges {
		doc.Graph.Edges = append(doc.Graph.Edges, gxEdge{ID: "e" + strconv.Itoa(i), Source: e.From, Target: e.To, Label: e.Label})
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	_ = enc.Encode(doc)
	return buf.Bytes()
}
