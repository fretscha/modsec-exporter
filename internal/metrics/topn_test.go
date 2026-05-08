package metrics

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// gatherText returns text-format exposition for the registered collectors.
func gatherText(t *testing.T, r *prometheus.Registry) string {
	t.Helper()
	mfs, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			t.Fatal(err)
		}
	}
	return buf.String()
}

func TestTopN_CapsAndOrders(t *testing.T) {
	tn := NewTopN(3, "test")
	tn.Observe("1.1.1.1", "US", "100", 5, 1)
	tn.Observe("2.2.2.2", "DE", "200", 50, 4)
	tn.Observe("3.3.3.3", "FR", "300", 10, 2)
	tn.Observe("4.4.4.4", "GB", "400", 100, 7) // bumps 1.1.1.1 (lowest score)

	r := prometheus.NewRegistry()
	r.MustRegister(tn)

	s := gatherText(t, r)
	for _, ip := range []string{"2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		if !strings.Contains(s, `client_ip="`+ip+`"`) {
			t.Errorf("missing %s; got:\n%s", ip, s)
		}
	}
	if strings.Contains(s, `client_ip="1.1.1.1"`) {
		t.Errorf("1.1.1.1 should have been bumped out:\n%s", s)
	}
}

func TestTopN_ResetClearsState(t *testing.T) {
	tn := NewTopN(2, "test")
	tn.Observe("1.1.1.1", "US", "100", 5, 1)
	tn.Reset()

	r := prometheus.NewRegistry()
	r.MustRegister(tn)
	if s := gatherText(t, r); strings.Contains(s, "1.1.1.1") {
		t.Fatalf("state not cleared; got:\n%s", s)
	}
}

func TestTopN_ZeroCapIsNoop(t *testing.T) {
	tn := NewTopN(0, "test")
	tn.Observe("1.1.1.1", "US", "100", 999, 999)
	r := prometheus.NewRegistry()
	r.MustRegister(tn)
	if s := gatherText(t, r); strings.Contains(s, "1.1.1.1") {
		t.Fatalf("cap=0 must drop everything; got:\n%s", s)
	}
}
