package incident

import "testing"

func TestParseSeverity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     string
		want   Severity
		wantOK bool
	}{
		{name: "info", in: "info", want: SeverityInfo, wantOK: true},
		{name: "minor", in: "minor", want: SeverityMinor, wantOK: true},
		{name: "major", in: "major", want: SeverityMajor, wantOK: true},
		{name: "critical", in: "critical", want: SeverityCritical, wantOK: true},
		{name: "unknown is a legal configured value", in: "unknown", want: SeverityUnknown, wantOK: true},
		{name: "garbage is rejected so config can fail at load", in: "catastrophic", want: SeverityUnknown, wantOK: false},
		{name: "empty is rejected", in: "", want: SeverityUnknown, wantOK: false},
		{name: "case sensitive", in: "Major", want: SeverityUnknown, wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseSeverity(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("ParseSeverity(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestSeverityStringIsStable(t *testing.T) {
	// These strings are metric label values and notification text. Changing one
	// silently breaks every dashboard query that filters on it.
	for _, tc := range []struct {
		in   Severity
		want string
	}{
		{SeverityUnknown, "unknown"},
		{SeverityInfo, "info"},
		{SeverityMinor, "minor"},
		{SeverityMajor, "major"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
}

func TestStatusStringIsStable(t *testing.T) {
	for _, tc := range []struct {
		in   Status
		want string
	}{
		{StatusOpen, "open"},
		{StatusResolved, "resolved"},
		{StatusUnknown, "unknown"},
		{Status(42), "unknown"},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("Status(%d).String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
}

func TestPreferredTitle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		titles   map[string]string
		prefer   string
		wantText string
		wantLang string
	}{
		{
			name:     "preferred language wins",
			titles:   map[string]string{"en": "Network degradation", "zh": "网络异常"},
			prefer:   "en",
			wantText: "Network degradation",
			wantLang: "en",
		},
		{
			// Real upstream records ship an empty English description; a naive
			// reader produces a blank alert.
			name:     "empty preferred falls back",
			titles:   map[string]string{"en": "", "zh": "网络异常"},
			prefer:   "en",
			wantText: "网络异常",
			wantLang: "zh",
		},
		{
			name:     "whitespace-only preferred falls back",
			titles:   map[string]string{"en": "   \n\t ", "zh": "网络异常"},
			prefer:   "en",
			wantText: "网络异常",
			wantLang: "zh",
		},
		{
			name:     "missing preferred key falls back",
			titles:   map[string]string{"zh": "网络异常"},
			prefer:   "en",
			wantText: "网络异常",
			wantLang: "zh",
		},
		{
			name:     "all blank yields a placeholder, never an empty alert",
			titles:   map[string]string{"en": "", "zh": "  "},
			prefer:   "en",
			wantText: "(untitled #13)",
			wantLang: "none",
		},
		{
			name:     "no titles at all yields a placeholder",
			titles:   nil,
			prefer:   "en",
			wantText: "(untitled #13)",
			wantLang: "none",
		},
		{
			name:     "surrounding whitespace is trimmed",
			titles:   map[string]string{"en": "  Network degradation  "},
			prefer:   "en",
			wantText: "Network degradation",
			wantLang: "en",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, lang := PreferredTitle(tc.titles, tc.prefer, "13")
			if text != tc.wantText || lang != tc.wantLang {
				t.Errorf("got (%q, %q), want (%q, %q)", text, lang, tc.wantText, tc.wantLang)
			}
		})
	}
}

// Fallback must be deterministic across runs. Go randomizes map iteration, so a
// title chosen by iteration order would change between two polls of identical
// data — indistinguishable from a real incident update.
func TestPreferredTitleFallbackIsDeterministic(t *testing.T) {
	titles := map[string]string{"en": "", "ja": "障害", "zh": "网络异常", "de": "Störung"}
	wantText, wantLang := PreferredTitle(titles, "en", "13")
	for i := 0; i < 200; i++ {
		text, lang := PreferredTitle(titles, "en", "13")
		if text != wantText || lang != wantLang {
			t.Fatalf("iteration %d: got (%q, %q), want (%q, %q)", i, text, lang, wantText, wantLang)
		}
	}
	if wantLang != "de" {
		t.Errorf("fallback language = %q, want %q (sorted remainder)", wantLang, "de")
	}
}

func TestKeyString(t *testing.T) {
	k := Key{SourceID: "huawei-intl", ProviderID: "13"}
	if got, want := k.String(), "huawei-intl/13"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
