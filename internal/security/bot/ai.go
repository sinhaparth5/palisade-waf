package bot

import "strings"

// AI crawler categories (issue #187).
const (
	AITraining = "training" // collects content for model training
	AISearch   = "search"   // indexes for AI answer engines
	AIUser     = "user"     // fetches a page a user asked an assistant about
)

// AICategories lists the categories in display and encoding order.
var AICategories = []string{AITraining, AISearch, AIUser}

// AI crawler policy actions. A category with no action is handled like any
// other client, the behaviour before the policy existed.
const (
	AIAllow     = "allow"     // verified crawlers skip the challenge gate
	AIChallenge = "challenge" // always challenged
	AIBlock     = "block"     // 403, verified or not
)

// ValidAIAction reports whether a is a policy action.
func ValidAIAction(a string) bool {
	return a == AIAllow || a == AIChallenge || a == AIBlock
}

// AIPolicy maps a category to its action. Stored as "training=block,user=allow";
// a missing category inherits (per service) or means no policy (global).
type AIPolicy map[string]string

// ParseAIPolicy decodes s, dropping unknown categories and actions.
func ParseAIPolicy(s string) AIPolicy {
	p := AIPolicy{}
	for kv := range strings.SplitSeq(s, ",") {
		k, v, _ := strings.Cut(kv, "=")
		if ValidAIAction(v) && (k == AITraining || k == AISearch || k == AIUser) {
			p[k] = v
		}
	}
	return p
}

// String encodes p in AICategories order.
func (p AIPolicy) String() string {
	var parts []string
	for _, c := range AICategories {
		if v := p[c]; v != "" {
			parts = append(parts, c+"="+v)
		}
	}
	return strings.Join(parts, ",")
}
