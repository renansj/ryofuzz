package vulns

import "testing"

// expectedModuleCount guards against accidental loss of a module during the
// registry migration (the pre-registry Select listed 48 modules).
const expectedModuleCount = 48

func TestRegistryCount(t *testing.T) {
	if got := len(AllModules()); got != expectedModuleCount {
		t.Errorf("registry has %d modules, expected %d", got, expectedModuleCount)
	}
}

func TestRegistryNamesUniqueAndMatch(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range AllModules() {
		if seen[m.Name()] {
			t.Errorf("duplicate module name: %s", m.Name())
		}
		seen[m.Name()] = true
	}
}

func TestEveryModuleHasIntrusiveness(t *testing.T) {
	for _, r := range registry {
		if !r.hasTag(TagSafe) && !r.hasTag(TagIntrusive) {
			t.Errorf("module %q has no intrusiveness tag (safe|intrusive)", r.name)
		}
	}
}

func TestSelectByName(t *testing.T) {
	sel := Select([]string{"sqli", "xss"})
	if len(sel) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(sel))
	}
	names := map[string]bool{sel[0].Name(): true, sel[1].Name(): true}
	if !names["sqli"] || !names["xss"] {
		t.Errorf("expected sqli and xss, got %v", names)
	}
}

func TestSelectAll(t *testing.T) {
	if len(Select([]string{"all"})) != expectedModuleCount {
		t.Errorf("Select(all) should return all %d modules", expectedModuleCount)
	}
}

func TestSelectByTag(t *testing.T) {
	inj := Select([]string{"tag:injection"})
	if len(inj) == 0 {
		t.Fatal("expected some injection modules")
	}
	for _, m := range inj {
		tags := TagsFor(m.Name())
		found := false
		for _, tg := range tags {
			if tg == TagInjection {
				found = true
			}
		}
		if !found {
			t.Errorf("module %q selected by tag:injection but lacks the tag", m.Name())
		}
	}
}

func TestSelectUnknownReturnsEmpty(t *testing.T) {
	if got := Select([]string{"does-not-exist"}); len(got) != 0 {
		t.Errorf("unknown selector should yield 0 modules, got %d", len(got))
	}
}
