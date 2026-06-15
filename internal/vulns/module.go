package vulns

import (
	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// VulnModule interface para cada classe de vulnerabilidade
type VulnModule interface {
	Name() string
	Description() string
	GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload
	Detect(payload mutator.Payload, baselineBody string, baselineStatus int, baselineTime int64, respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding
}

// Finding resultado de detecção
type Finding struct {
	Module      string
	Severity    string // critical, high, medium, low, info
	Confidence  string // confirmed, high, medium, low
	Title       string
	Description string
	Payload     string
	Point       input.InjectionPoint
	Evidence    string
	OWASP       string // ex: "A03:2021 Injection"
	CWE         string // ex: "CWE-89"
	Request     string
	Response    string
}

// Select retorna os módulos selecionados
func Select(tests []string) []VulnModule {
	all := []VulnModule{
		&SQLiModule{},
		&XSSModule{},
		&SSTIModule{},
		&SSRFModule{},
		&CMDiModule{},
		&LFIModule{},
		&NoSQLiModule{},
		&XXEModule{},
		&IDORModule{},
		&OpenRedirectModule{},
		&CRLFModule{},
		&PrototypePollutionModule{},
		&JWTModule{},
		&MassAssignmentModule{},
		&RaceConditionModule{},
		&HTTPSmugglingModule{},
		&CORSModule{},
		&CSPBypassModule{},
		&GraphQLModule{},
		&DeserializationModule{},
		&LDAPiModule{},
		&XPathiModule{},
		&BusinessLogicModule{},
		&RateLimitModule{},
		&VerbTamperModule{},
		&HostHeaderModule{},
		&CachePoisonModule{},
		&WebSocketModule{},
		&PromptInjectionModule{},
		&CacheDeceptionModule{},
		&OAuthModule{},
		&UploadModule{},
		&PwResetModule{},
		&HPPModule{},
		&CSVInjectModule{},
		&EmailInjectModule{},
		&XSSIModule{},
		&ELInjectModule{},
		&InfoLeakModule{},
		&CSRFModule{},
		&TakeoverModule{},
		&SAMLModule{},
		&ClickjackModule{},
		&ReDoSModule{},
		&XSLTModule{},
		&SessionModule{},
		&UserEnumModule{},
		&ZipSlipModule{},
	}

	if len(tests) == 1 && tests[0] == "all" {
		return all
	}

	var selected []VulnModule
	testMap := make(map[string]bool)
	for _, t := range tests {
		testMap[t] = true
	}
	for _, m := range all {
		if testMap[m.Name()] {
			selected = append(selected, m)
		}
	}
	return selected
}
