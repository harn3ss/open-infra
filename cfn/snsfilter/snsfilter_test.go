package snsfilter

import "testing"

func attrs(kv ...string) map[string]Attr {
	m := map[string]Attr{}
	for i := 0; i+2 < len(kv)+1; i += 3 {
		m[kv[i]] = Attr{Type: kv[i+1], Value: kv[i+2]}
	}
	return m
}

func mustParse(t *testing.T, doc, scope string) *Policy {
	t.Helper()
	p, err := Parse(doc, scope)
	if err != nil {
		t.Fatalf("Parse(%s): %v", doc, err)
	}
	return p
}

func TestAttributes(t *testing.T) {
	cases := []struct {
		policy string
		attrs  map[string]Attr
		want   bool
	}{
		{`{"color":["red","blue"]}`, attrs("color", "String", "red"), true},
		{`{"color":["red","blue"]}`, attrs("color", "String", "green"), false},
		{`{"color":["red"]}`, attrs(), false},
		{`{"color":["red"],"size":["L"]}`, attrs("color", "String", "red"), false}, // AND
		{`{"color":["red"],"size":["L"]}`, attrs("color", "String", "red", "size", "String", "L"), true},
		{`{"price":[100]}`, attrs("price", "Number", "100.0"), true},
		{`{"price":[100]}`, attrs("price", "String", "100"), false}, // a number matches a Number attribute
		{`{"price":[{"numeric":[">",0,"<=",150]}]}`, attrs("price", "Number", "150"), true},
		{`{"price":[{"numeric":[">",0,"<=",150]}]}`, attrs("price", "Number", "151"), false},
		{`{"price":[{"numeric":["<",10]}]}`, attrs("price", "Number", "x"), false},
		{`{"c":[{"prefix":"eu-"}]}`, attrs("c", "String", "eu-west"), true},
		{`{"c":[{"suffix":".png"}]}`, attrs("c", "String", "a.jpg"), false},
		{`{"c":[{"equals-ignore-case":"RED"}]}`, attrs("c", "String", "red"), true},
		{`{"c":[{"anything-but":["red","blue"]}]}`, attrs("c", "String", "green"), true},
		{`{"c":[{"anything-but":["red","blue"]}]}`, attrs("c", "String", "red"), false},
		{`{"c":[{"anything-but":"red"}]}`, attrs(), false}, // anything-but needs the attribute
		{`{"c":[{"anything-but":{"prefix":"tmp-"}}]}`, attrs("c", "String", "tmp-1"), false},
		{`{"c":[{"exists":false}]}`, attrs(), true},
		{`{"c":[{"exists":true}]}`, attrs("c", "Binary", "AA=="), true},
		{`{"c":["x"]}`, attrs("c", "Binary", "x"), false}, // a Binary attribute matches no value
		{`{"ip":[{"cidr":"10.0.0.0/24"}]}`, attrs("ip", "String", "10.0.0.7"), true},
		{`{"ip":[{"cidr":"10.0.0.0/24"}]}`, attrs("ip", "String", "10.0.1.7"), false},
		{`{"tags":["b"]}`, attrs("tags", "String.Array", `["a","b"]`), true},
		{`{"tags":[2]}`, attrs("tags", "String.Array", `["a",2]`), true},
		{`{"tags":[{"anything-but":["b"]}]}`, attrs("tags", "String.Array", `["a","b"]`), false},
		{`{"c":["x"],"$or":[{"a":["1"]},{"b":["2"]}]}`, attrs("c", "String", "x", "b", "String", "2"), true},
		{`{"c":["x"],"$or":[{"a":["1"]},{"b":["2"]}]}`, attrs("c", "String", "x"), false},
		{`{"c":["x"]}`, attrs("c", "String.custom", "x"), true}, // a custom type is its base type
	}
	for _, c := range cases {
		if got := mustParse(t, c.policy, "").MatchAttributes(c.attrs); got != c.want {
			t.Errorf("%s on %v = %v, want %v", c.policy, c.attrs, got, c.want)
		}
	}
}

func TestBody(t *testing.T) {
	cases := []struct {
		policy, body string
		want         bool
	}{
		{`{"order":{"status":["paid"]}}`, `{"order":{"status":"paid","n":1}}`, true},
		{`{"order":{"status":["paid"]}}`, `{"order":{"status":"open"}}`, false},
		{`{"order":{"status":["paid"]}}`, `{"other":1}`, false},
		{`{"items":{"sku":["a"]}}`, `{"items":[{"sku":"b"},{"sku":"a"}]}`, true},
		{`{"flag":[true]}`, `{"flag":true}`, true},
		{`{"flag":[null]}`, `{"flag":null}`, true},
		{`{"n":[{"numeric":[">=",5]}]}`, `{"n":5}`, true},
		{`{"n":[{"exists":false}]}`, `{"m":1}`, true},
		{`{"a":["x"]}`, `not json`, false},
		{`{"a":["x"]}`, `["x"]`, false},
	}
	for _, c := range cases {
		if got := mustParse(t, c.policy, ScopeBody).MatchBody(c.body); got != c.want {
			t.Errorf("%s on %s = %v, want %v", c.policy, c.body, got, c.want)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	for _, c := range []struct{ doc, scope string }{
		{`[]`, ""},
		{`{}`, ""},
		{`{"a":"x"}`, ""},
		{`{"a":[]}`, ""},
		{`{"a":{"b":["x"]}}`, ""}, // nested is body only
		{`{"a":[true]}`, ""},
		{`{"a":[{"wildcard":"x*"}]}`, ""},
		{`{"a":[{"numeric":["<",5,">",1]}]}`, ""},
		{`{"a":[{"numeric":[">",5,"<",1]}]}`, ""},
		{`{"a":[{"cidr":"nope"}]}`, ""},
		{`{"a":[{"prefix":"x","suffix":"y"}]}`, ""},
		{`{"$or":[{"a":["x"]}]}`, ""},
		{`{"a":["1"],"b":["1"],"c":["1"],"d":["1"],"e":["1"],"f":["1"]}`, ""},
		{`{"a":["x"]}`, "Everything"},
	} {
		if _, err := Parse(c.doc, c.scope); err == nil {
			t.Errorf("Parse(%s, %q) accepted, want a refusal", c.doc, c.scope)
		}
	}
	// 151 combinations.
	big := `{"a":["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16"],"b":["1","2","3","4","5","6","7","8","9","10"]}`
	if _, err := Parse(big, ""); err == nil {
		t.Error("160 combinations accepted")
	}
}
