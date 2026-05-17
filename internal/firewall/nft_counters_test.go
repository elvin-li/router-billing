package firewall

import "testing"

func TestParseCountersWithCounterFlag(t *testing.T) {
	j := `{
	  "nftables": [
	    {"metainfo": {}},
	    {"set": {
	      "family": "inet", "table": "billing", "name": "mac_paid",
	      "type": "ether_addr", "flags": ["counter"],
	      "elem": [
	        {"elem": {"val": "aa:bb:cc:dd:ee:ff", "counter": {"packets": 100, "bytes": 12345}}},
	        {"elem": {"val": "11:22:33:44:55:66", "counter": {"packets": 7, "bytes": 0}}}
	      ]
	    }}
	  ]
	}`
	got, err := parseCounters(j)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got["AA:BB:CC:DD:EE:FF"].Packets != 100 || got["AA:BB:CC:DD:EE:FF"].Bytes != 12345 {
		t.Errorf("first mac: %+v", got["AA:BB:CC:DD:EE:FF"])
	}
	if got["11:22:33:44:55:66"].Packets != 7 {
		t.Errorf("second mac: %+v", got["11:22:33:44:55:66"])
	}
}

func TestParseCountersNoFlag(t *testing.T) {
	j := `{
	  "nftables": [
	    {"set": {"name": "mac_paid", "elem": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]}}
	  ]
	}`
	got, err := parseCounters(j)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if c := got["AA:BB:CC:DD:EE:FF"]; c.Packets != 0 || c.Bytes != 0 {
		t.Errorf("no-flag should report zero, got %+v", c)
	}
}

func TestParseCountersEmpty(t *testing.T) {
	got, err := parseCounters("")
	if err != nil || len(got) != 0 {
		t.Errorf("empty input: got=%v err=%v", got, err)
	}
	got, err = parseCounters(`{"nftables":[]}`)
	if err != nil || len(got) != 0 {
		t.Errorf("empty nftables: got=%v err=%v", got, err)
	}
}

func TestParseCountersBadJSON(t *testing.T) {
	_, err := parseCounters("not json")
	if err == nil {
		t.Error("bad json should error")
	}
}
