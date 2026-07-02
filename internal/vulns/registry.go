package vulns

import "sort"

// Tag classifies a module by category and intrusiveness so the scanner can
// select modules by capability (e.g. only "injection", or exclude
// "intrusive") instead of listing names. See review A4.
type Tag string

const (
	// Categories
	TagInjection  Tag = "injection"
	TagAuth       Tag = "auth"
	TagDisclosure Tag = "disclosure"
	TagClient     Tag = "client"
	TagProtocol   Tag = "protocol"
	TagLogic      Tag = "logic"
	TagDoS        Tag = "dos"
	TagLLM        Tag = "llm"

	// Intrusiveness
	TagSafe      Tag = "safe"      // read-only / low side effect
	TagIntrusive Tag = "intrusive" // may write/alter state but not destructive
)

// registration ties a module factory to its metadata.
type registration struct {
	name    string
	factory func() VulnModule
	tags    []Tag
}

// registry is the ordered list of all known modules. Order is preserved so
// scan output stays deterministic.
var registry []registration

// byName indexes registry entries for O(1) name lookup.
var byName = map[string]int{}

// register adds a module to the registry. Called from registerAll (kept in one
// place to avoid editing 48 files); new modules can also register from init().
func register(name string, factory func() VulnModule, tags ...Tag) {
	if _, dup := byName[name]; dup {
		return // ignore duplicate registration
	}
	byName[name] = len(registry)
	registry = append(registry, registration{name: name, factory: factory, tags: tags})
}

// hasTag reports whether a registration carries the given tag.
func (r registration) hasTag(t Tag) bool {
	for _, x := range r.tags {
		if x == t {
			return true
		}
	}
	return false
}

// AllModules returns a fresh instance of every registered module, in order.
func AllModules() []VulnModule {
	out := make([]VulnModule, 0, len(registry))
	for _, r := range registry {
		out = append(out, r.factory())
	}
	return out
}

// SelectByTag returns modules carrying the given tag, in registry order.
func SelectByTag(t Tag) []VulnModule {
	var out []VulnModule
	for _, r := range registry {
		if r.hasTag(t) {
			out = append(out, r.factory())
		}
	}
	return out
}

// Tags returns the sorted set of tags a module declares (for reporting/UX).
func TagsFor(name string) []Tag {
	i, ok := byName[name]
	if !ok {
		return nil
	}
	tags := append([]Tag(nil), registry[i].tags...)
	sort.Slice(tags, func(a, b int) bool { return tags[a] < tags[b] })
	return tags
}

func init() {
	registerAll()
}

// registerAll wires every built-in module with its category and intrusiveness
// tags. Kept as one table so the taxonomy is reviewable in a single place.
func registerAll() {
	register("sqli", func() VulnModule { return &SQLiModule{} }, TagInjection, TagIntrusive)
	register("xss", func() VulnModule { return &XSSModule{} }, TagInjection, TagSafe)
	register("ssti", func() VulnModule { return &SSTIModule{} }, TagInjection, TagIntrusive)
	register("ssrf", func() VulnModule { return &SSRFModule{} }, TagInjection, TagIntrusive)
	register("cmdi", func() VulnModule { return &CMDiModule{} }, TagInjection, TagIntrusive)
	register("lfi", func() VulnModule { return &LFIModule{} }, TagInjection, TagSafe)
	register("nosqli", func() VulnModule { return &NoSQLiModule{} }, TagInjection, TagIntrusive)
	register("xxe", func() VulnModule { return &XXEModule{} }, TagInjection, TagIntrusive)
	register("idor", func() VulnModule { return &IDORModule{} }, TagAuth, TagSafe)
	register("redirect", func() VulnModule { return &OpenRedirectModule{} }, TagInjection, TagSafe)
	register("crlf", func() VulnModule { return &CRLFModule{} }, TagInjection, TagIntrusive)
	register("prototype", func() VulnModule { return &PrototypePollutionModule{} }, TagInjection, TagIntrusive)
	register("jwt", func() VulnModule { return &JWTModule{} }, TagAuth, TagSafe)
	register("mass-assign", func() VulnModule { return &MassAssignmentModule{} }, TagLogic, TagIntrusive)
	register("race", func() VulnModule { return &RaceConditionModule{} }, TagLogic, TagIntrusive)
	register("smuggling", func() VulnModule { return &HTTPSmugglingModule{} }, TagProtocol, TagIntrusive)
	register("cors", func() VulnModule { return &CORSModule{} }, TagClient, TagSafe)
	register("csp", func() VulnModule { return &CSPBypassModule{} }, TagClient, TagSafe)
	register("graphql", func() VulnModule { return &GraphQLModule{} }, TagInjection, TagSafe)
	register("deser", func() VulnModule { return &DeserializationModule{} }, TagInjection, TagIntrusive)
	register("ldapi", func() VulnModule { return &LDAPiModule{} }, TagInjection, TagIntrusive)
	register("xpathi", func() VulnModule { return &XPathiModule{} }, TagInjection, TagIntrusive)
	register("logic", func() VulnModule { return &BusinessLogicModule{} }, TagLogic, TagIntrusive)
	register("ratelimit", func() VulnModule { return &RateLimitModule{} }, TagLogic, TagIntrusive)
	register("verb", func() VulnModule { return &VerbTamperModule{} }, TagAuth, TagSafe)
	register("hostheader", func() VulnModule { return &HostHeaderModule{} }, TagInjection, TagIntrusive)
	register("cache", func() VulnModule { return &CachePoisonModule{} }, TagClient, TagIntrusive)
	register("ws", func() VulnModule { return &WebSocketModule{} }, TagProtocol, TagSafe)
	register("prompt", func() VulnModule { return &PromptInjectionModule{} }, TagLLM, TagSafe)
	register("cache-deception", func() VulnModule { return &CacheDeceptionModule{} }, TagClient, TagSafe)
	register("oauth", func() VulnModule { return &OAuthModule{} }, TagAuth, TagSafe)
	register("upload", func() VulnModule { return &UploadModule{} }, TagInjection, TagIntrusive)
	register("pwreset", func() VulnModule { return &PwResetModule{} }, TagAuth, TagIntrusive)
	register("hpp", func() VulnModule { return &HPPModule{} }, TagInjection, TagSafe)
	register("csv", func() VulnModule { return &CSVInjectModule{} }, TagInjection, TagSafe)
	register("email-inj", func() VulnModule { return &EmailInjectModule{} }, TagInjection, TagIntrusive)
	register("xssi", func() VulnModule { return &XSSIModule{} }, TagClient, TagSafe)
	register("el", func() VulnModule { return &ELInjectModule{} }, TagInjection, TagIntrusive)
	register("infoleak", func() VulnModule { return &InfoLeakModule{} }, TagDisclosure, TagSafe)
	register("csrf", func() VulnModule { return &CSRFModule{} }, TagClient, TagSafe)
	register("takeover", func() VulnModule { return &TakeoverModule{} }, TagDisclosure, TagSafe)
	register("saml", func() VulnModule { return &SAMLModule{} }, TagAuth, TagIntrusive)
	register("clickjack", func() VulnModule { return &ClickjackModule{} }, TagClient, TagSafe)
	register("redos", func() VulnModule { return &ReDoSModule{} }, TagDoS, TagIntrusive)
	register("xslt", func() VulnModule { return &XSLTModule{} }, TagInjection, TagIntrusive)
	register("session", func() VulnModule { return &SessionModule{} }, TagAuth, TagSafe)
	register("userenum", func() VulnModule { return &UserEnumModule{} }, TagAuth, TagSafe)
	register("zipslip", func() VulnModule { return &ZipSlipModule{} }, TagInjection, TagIntrusive)
}
