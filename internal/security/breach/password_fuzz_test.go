package breach

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
)

// FuzzBreachPassword (issue #307): Password never panics and returns only
// the Basic auth password or a value the body itself decodes to.
func FuzzBreachPassword(f *testing.F) {
	f.Add("application/x-www-form-urlencoded", "user=a&password=hunter2", "")
	f.Add("application/json", `{"user":{"password":"s3cret"}}`, "")
	f.Add("application/vnd.api+json; charset=utf-8", `{"a":{"b":{"c":{"d":{"pass":"deep"}}}}}`, "")
	f.Add("application/json", `[{"password":"x"}]`, "")
	f.Add("application/x-www-form-urlencoded", "password=%zz;pwd=%41", "Basic dTpw")
	f.Add("multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\npw\r\n--x--", "")
	f.Fuzz(func(t *testing.T, ctype, body, auth string) {
		r, _ := http.NewRequest(http.MethodPost, "/login", nil)
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("Authorization", auth)
		pw := Password(r, []byte(body), nil)
		if pw == "" {
			return
		}
		if _, basic, ok := r.BasicAuth(); ok && basic == pw {
			return
		}
		if v, err := url.ParseQuery(body); err == nil {
			for _, vs := range v {
				if slices.Contains(vs, pw) {
					return
				}
			}
		}
		var v any
		if json.Unmarshal([]byte(body), &v) == nil && slices.Contains(jsonStrings(v, nil), pw) {
			return
		}
		t.Fatalf("Password = %q, not in the body %q or Basic auth", pw, body)
	})
}

// jsonStrings collects every string value under JSON objects.
func jsonStrings(v any, out []string) []string {
	if m, ok := v.(map[string]any); ok {
		for _, val := range m {
			if s, ok := val.(string); ok {
				out = append(out, s)
			}
			out = jsonStrings(val, out)
		}
	}
	return out
}
