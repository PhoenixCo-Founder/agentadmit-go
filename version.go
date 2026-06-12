package agentadmit

import "runtime/debug"

// userAgent is sent on every request to the AgentAdmit hosted service.
// The version is read from Go module build info, so tagging a release is the
// whole release step — the previous hand-maintained constant shipped v1.1.0
// still reporting "agentadmit-go/1.0.0".
var userAgent = func() string {
	const modulePath = "github.com/PhoenixCo-Founder/agentadmit-go"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Path == modulePath && info.Main.Version != "" && info.Main.Version != "(devel)" {
			return "agentadmit-go/" + info.Main.Version
		}
		for _, dep := range info.Deps {
			if dep.Path == modulePath {
				return "agentadmit-go/" + dep.Version
			}
		}
	}
	return "agentadmit-go/dev"
}()
