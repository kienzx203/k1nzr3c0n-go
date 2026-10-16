package db

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"slices"
)

// fresh task, returning their ids. Unique stamp keeps concurrent runs isolated.
func exportFixture(t *testing.T, d *DB, as *AssetStore, stamp int64) (taskID int64, ids []int64) {
	t.Helper()
	taskID = 900000 + stamp%100000
	root, err := as.UpsertRootDomain(UpsertRootDomainReq{Domain: "export-root.example", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := as.UpsertSubdomain(UpsertSubdomainReq{Domain: "export-sub.export-root.example", RecordType: "A", RecordValue: []string{"203.0.113.77"}, TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	ip, err := as.UpsertIP(UpsertIPReq{IP: "203.0.113.77", BoundDomains: []string{"export-sub.export-root.example"}, TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	ids = []int64{root, sub, ip}
	t.Cleanup(func() {
		for _, id := range ids {
			d.Exec(`DELETE FROM assets WHERE id = $1`, id)
		}
	})
	return taskID, ids
}

// bulkSubdomains inserts n unique subdomains under a throwaway root and returns
// their ids with a cleanup. Used to pin the no-cap export guarantee.
func bulkSubdomains(t *testing.T, d *DB, as *AssetStore, stamp int64, n int) []int64 {
	t.Helper()
	root := fmt.Sprintf("bulk%d.example", stamp)
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		id, err := as.UpsertSubdomain(UpsertSubdomainReq{
			Domain:      fmt.Sprintf("h%d.%s", i, root),
			RecordType:  "A",
			RecordValue: []string{fmt.Sprintf("203.0.%d.%d", stamp%256, i%256)},
			TaskID:      700000 + stamp%100000,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			d.Exec(`DELETE FROM assets WHERE id = $1`, id)
		}
	})
	return ids
}

// TestListAssetsForExportTypeNoCap pins the no-cap guarantee: more than 50
// assets of one type, exported with only Type set (the plain path that must not
// reuse QueryByType's UI paging), must return every row.
func TestListAssetsForExportTypeNoCap(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	stamp := time.Now().UnixNano() % 100000
	want := bulkSubdomains(t, d, as, stamp, 55)

	got, err := as.ListAssetsForExport(AssetExportFilter{Type: "subdomain"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gotSet := map[int64]bool{}
	for _, a := range got {
		if a.Type != "subdomain" {
			t.Fatalf("non-subdomain row %d type=%s", a.ID, a.Type)
		}
		gotSet[a.ID] = true
	}
	for _, id := range want {
		if !gotSet[id] {
			t.Fatalf("subdomain %d missing: export returned %d rows, want at least %d (QueryByType cap regression?)", id, len(got), len(want))
		}
	}
}

// TestListAssetsForExportAllTypesPresent pins that the bare filter (scope=all)
// returns every type, not the old root_domain-only default.
func TestListAssetsForExportAllTypesPresent(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	stamp := time.Now().UnixNano() % 100000
	taskID := int64(600000 + stamp%100000)
	// Mix: root_domain + subdomain + ip + service + endpoint + app.
	if _, err := as.UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("mix%d.example", stamp), TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertSubdomain(UpsertSubdomainReq{Domain: fmt.Sprintf("a.mix%d.example", stamp), RecordType: "A", RecordValue: []string{fmt.Sprintf("198.51.100.%d", stamp%256)}, TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertIP(UpsertIPReq{IP: fmt.Sprintf("198.51.100.%d", stamp%256), TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertHTTPService(UpsertHTTPServiceReq{URL: fmt.Sprintf("https://a.mix%d.example", stamp), TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertEndpoint(UpsertEndpointReq{URL: fmt.Sprintf("https://a.mix%d.example/api", stamp), Method: "GET", TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertApp(UpsertAppReq{Name: "Mix", BundleID: fmt.Sprintf("com.mix%d.app", stamp), TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM assets WHERE $1 = ANY(task_ids)`, taskID)
	})

	got, err := as.ListAssetsForExport(AssetExportFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, a := range got {
		types[a.Type] = true
	}
	for _, want := range []string{"root_domain", "subdomain", "ip", "service", "endpoint", "app"} {
		if !types[want] {
			t.Fatalf("scope=all missing type %q; got types: %v", want, keysOf(types))
		}
	}
}

func TestListAssetsForExportSelected(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	_, ids := exportFixture(t, d, as, time.Now().UnixNano()%1000000)

	got, err := as.ListAssetsForExport(AssetExportFilter{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ids) {
		t.Fatalf("selected export = %d rows, want %d", len(got), len(ids))
	}
	gotIDs := map[int64]bool{}
	for _, a := range got {
		gotIDs[a.ID] = true
	}
	for _, id := range ids {
		if !gotIDs[id] {
			t.Fatalf("selected id %d missing from export", id)
		}
	}
}

func TestListAssetsForExportFilteredByTask(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	taskID, ids := exportFixture(t, d, as, time.Now().UnixNano()%1000000)

	got, err := as.ListAssetsForExport(AssetExportFilter{TaskID: taskID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ids) {
		t.Fatalf("task export = %d rows, want %d", len(got), len(ids))
	}
	for _, a := range got {
		if !slices.Contains(a.TaskIDs, taskID) {
			t.Fatalf("asset %d not scoped to task %d: %v", a.ID, taskID, a.TaskIDs)
		}
	}
}

func TestListAssetsForExportFilteredByType(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	taskID, _ := exportFixture(t, d, as, time.Now().UnixNano()%1000000)

	got, err := as.ListAssetsForExport(AssetExportFilter{TaskID: taskID, Type: "subdomain"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != "subdomain" {
		t.Fatalf("type filter returned %+v", got)
	}
}

func TestListAssetsForExportFilteredByDSL(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	taskID, _ := exportFixture(t, d, as, time.Now().UnixNano()%1000000)

	got, err := as.ListAssetsForExport(AssetExportFilter{TaskID: taskID, DSL: "domain=export-sub"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != "subdomain" {
		t.Fatalf("dsl filter returned %+v", got)
	}
}

func TestListAssetsForExportFilteredByCompany(t *testing.T) {
	d, as, cs := testSetup(t)
	defer d.Close()
	stamp := time.Now().UnixNano() % 1000000
	companyID, _, _, _, _, err := cs.CreateCompanyWithScope(
		"Export Co "+strconv.FormatInt(stamp, 10), "",
		[]ScopeInput{{Kind: "domain", Value: "export-root.example"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.DeleteCompany(companyID) }()

	taskID, _ := exportFixture(t, d, as, stamp)
	if err := cs.RecomputeAttribution(); err != nil {
		t.Fatal(err)
	}

	got, err := as.ListAssetsForExport(AssetExportFilter{CompanyID: companyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("company export returned no rows")
	}
	for _, a := range got {
		if a.CompanyID == nil || *a.CompanyID != companyID {
			t.Fatalf("asset %d not attributed to company %d", a.ID, companyID)
		}
	}
	_ = taskID
}

func TestListAssetsForExportEmptyResult(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	got, err := as.ListAssetsForExport(AssetExportFilter{TaskID: 999999999}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %d rows", len(got))
	}
}

func TestListAssetsForExportRejectsBadDSL(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	_, err := as.ListAssetsForExport(AssetExportFilter{DSL: `nope_field = "x"`}, nil)
	if err == nil {
		t.Fatal("expected an error for invalid DSL, got nil")
	}
}
