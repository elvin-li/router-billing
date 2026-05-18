package server

import (
	"log"
	"strings"

	"router-billing/internal/config"
	"router-billing/internal/sms"
)

// buildSMSSender constructs the right SMS provider based on config. Returns
// a *sms.Sender with .P == nil when no provider is selected; callers should
// use .Available() to decide whether to expose SMS-dependent UI / handlers.
//
// Missing creds for a named provider are non-fatal — we log loudly and
// disable SMS so the rest of the system still boots. (Failing closed would
// strand a router whose admin typo'd an Aliyun key.)
func buildSMSSender(cfg config.SMSConfig) *sms.Sender {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "", "none", "off":
		return &sms.Sender{}
	case "console":
		log.Printf("sms: provider=console (dev mode — messages logged, not sent)")
		return &sms.Sender{P: sms.NewConsole(50)}
	case "aliyun":
		a := cfg.Aliyun
		if a.AccessKeyID == "" || a.AccessKeySecret == "" || a.SignName == "" || a.TemplateCode == "" {
			log.Printf("sms: provider=aliyun selected but credentials incomplete — disabled")
			return &sms.Sender{}
		}
		log.Printf("sms: provider=aliyun (sign=%s template=%s)", a.SignName, a.TemplateCode)
		return &sms.Sender{P: sms.NewAliyun(a.AccessKeyID, a.AccessKeySecret, a.SignName, a.TemplateCode)}
	default:
		log.Printf("sms: unknown provider %q — disabled", cfg.Provider)
		return &sms.Sender{}
	}
}
