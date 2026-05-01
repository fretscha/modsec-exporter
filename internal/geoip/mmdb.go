package geoip

import (
	"container/list"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// MMDB is a country+ASN lookup backed by a MaxMind-format DB.
// Compatible with IPInfo Country/ASN MMDBs and MaxMind GeoLite2.
type MMDB struct {
	db *maxminddb.Reader

	mu    sync.Mutex
	order *list.List // front = newest
	index map[string]*list.Element
	cap   int
}

// We probe each MMDB shape with its own struct because mixing field types
// across shapes (e.g. `country` as struct vs string) causes a partial decode
// failure that drops other fields.
//
// Three shapes encountered in the wild:
//   - IPInfo Lite/Bundle:   top-level "country_code":"US", string "asn":"AS15169"
//   - MaxMind GeoLite2-Country: nested {"country":{"iso_code":"US"}}
//   - MaxMind GeoLite2-ASN:     numeric "autonomous_system_number"
type ipinfoRecord struct {
	CountryCode string `maxminddb:"country_code"`
	ASN         string `maxminddb:"asn"`
}

type maxmindCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type maxmindASNRecord struct {
	ASN uint `maxminddb:"autonomous_system_number"`
}

type cacheEntry struct {
	key string
	val Result
}

// NewMMDB opens path and returns a Lookup. cacheCap caps the in-memory LRU
// (set 0 to disable caching).
func NewMMDB(path string, cacheCap int) (*MMDB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDB{
		db:    r,
		order: list.New(),
		index: make(map[string]*list.Element),
		cap:   cacheCap,
	}, nil
}

// Close releases the MMDB file handle.
func (m *MMDB) Close() error { return m.db.Close() }

// formatUint stringifies a uint without pulling in strconv just for ASN.
func formatUint(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Lookup returns Result{} for nil IPs or DB misses.
func (m *MMDB) Lookup(ip net.IP) Result {
	if ip == nil {
		return Result{}
	}
	key := ip.String()

	if m.cap > 0 {
		m.mu.Lock()
		if el, ok := m.index[key]; ok {
			m.order.MoveToFront(el)
			r := el.Value.(*cacheEntry).val
			m.mu.Unlock()
			return r
		}
		m.mu.Unlock()
	}

	res := Result{}

	// IPInfo shape — most common in modern bundles.
	var ipinfo ipinfoRecord
	if err := m.db.Lookup(ip, &ipinfo); err == nil {
		if ipinfo.CountryCode != "" {
			res.Country = ipinfo.CountryCode
		}
		if ipinfo.ASN != "" {
			res.ASN = strings.TrimPrefix(ipinfo.ASN, "AS")
		}
	}

	// MaxMind country shape — fill in if IPInfo didn't.
	if res.Country == "" {
		var mmc maxmindCountryRecord
		if err := m.db.Lookup(ip, &mmc); err == nil && mmc.Country.ISOCode != "" {
			res.Country = mmc.Country.ISOCode
		}
	}

	// MaxMind ASN shape — fill in if IPInfo didn't.
	if res.ASN == "" {
		var mma maxmindASNRecord
		if err := m.db.Lookup(ip, &mma); err == nil && mma.ASN != 0 {
			res.ASN = formatUint(mma.ASN)
		}
	}

	if m.cap > 0 {
		m.mu.Lock()
		el := m.order.PushFront(&cacheEntry{key: key, val: res})
		m.index[key] = el
		for m.order.Len() > m.cap {
			oldest := m.order.Back()
			m.order.Remove(oldest)
			delete(m.index, oldest.Value.(*cacheEntry).key)
		}
		m.mu.Unlock()
	}

	return res
}
