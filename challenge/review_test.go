package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

const reviewPort = "80"

type testCase struct {
	explanation           string
	method                string
	path                  string
	username              string
	password              string
	expectedCode          int
	expectedAccessGranted bool
	expectedReason        string
}

var testCases = []testCase{
	testCase{
		explanation:           "Success",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com/proxyauth",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: true,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Success",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com/proxyauth",
		username:              "teru",
		password:              "ilovejava",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: true,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Success",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com/proxyauth",
		username:              "toshi",
		password:              "iloveapex",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: true,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Success",
		method:                "POST",
		path:                  "/api/2/domains/appirio.com/proxyauth",
		username:              "jun",
		password:              "ilovetopcoder",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: true,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Success",
		method:                "POST",
		path:                  "/api/2/domains/appirio.com/proxyauth",
		username:              "narinder",
		password:              "ilovesamurai",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: true,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Success",
		method:                "POST",
		path:                  "/api/2/domains/appirio.com/proxyauth",
		username:              "chris",
		password:              "ilovesushi",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: true,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Password unmatch",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com/proxyauth",
		username:              "takumi",
		password:              "ilovegoa",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: false,
		expectedReason:        "denied by policy",
	},
	testCase{
		explanation:           "Username not found",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com/proxyauth",
		username:              "takumia",
		password:              "ilovego",
		expectedCode:          http.StatusOK,
		expectedAccessGranted: false,
		expectedReason:        "denied by policy",
	},
	testCase{
		explanation:           "Domain not found",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.coma/proxyauth",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "URL invalid 1",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com/proxyautha",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "URL invalid 2",
		method:                "POST",
		path:                  "/api/2/domains/topcoder.com",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "URL invalid 3",
		method:                "POST",
		path:                  "/api/2/domains/",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "URL invalid 4",
		method:                "POST",
		path:                  "/api/2",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "URL invalid 5",
		method:                "POST",
		path:                  "/api",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "URL invalid 6",
		method:                "POST",
		path:                  "/api/3/domains/topcoder.com/proxyauth",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
	testCase{
		explanation:           "Invalid method",
		method:                "GET",
		path:                  "/api/2/domains/topcoder.com/proxyauth",
		username:              "takumi",
		password:              "ilovego",
		expectedCode:          http.StatusNotFound,
		expectedAccessGranted: false,
		expectedReason:        "",
	},
}

func Test_review(t *testing.T) {
	for i, tc := range testCases {
		tc.password = reviewEncode(tc.password)

		review(t, i, tc)
	}
}

func review(t *testing.T, i int, tc testCase) {
	fmt.Printf("\nCase %d: %s\n%+v\n", i+1, tc.explanation, tc)

	v := url.Values{}
	v.Set("username", tc.username)
	v.Set("password", tc.password)

	var res *http.Response
	var err error

	switch tc.method {
	case "POST":
		res, err = http.PostForm("http://localhost:"+reviewPort+tc.path, v)
	case "GET":
		res, err = http.Get("http://localhost:" + reviewPort + tc.path)
	default:
		return
	}

	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println(res.StatusCode)

	if res.StatusCode != tc.expectedCode {
		t.Errorf("res.StatusCode = %d; want %d", res.StatusCode, tc.expectedCode)
		return
	}

	b, err := ioutil.ReadAll(res.Body)

	defer res.Body.Close()

	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println(string(b))

	if tc.expectedCode != http.StatusOK {
		return
	}

	if got, want := len(res.Header["Content-Type"]), 1; got != want {
		t.Errorf(`len(res.Header["Content-Type"]) = %d; want %d`, got, want)
		return
	}

	if got, want := res.Header["Content-Type"][0], "application/json"; got != want {
		t.Errorf(`res.Header["Content-Type"][0] = %s; want %s`, got, want)
		fmt.Println("*****", i)
		return
	}

	var m map[string]interface{}

	if err := json.Unmarshal(b, &m); err != nil {
		t.Error(err)
		return
	}

	if m["access_granted"] != tc.expectedAccessGranted {
		t.Errorf(`m["access_granted"] = %s; want %s`, m["access_granted"], tc.expectedAccessGranted)
		return
	}

	if tc.expectedReason != "" && m["reason"] != tc.expectedReason {
		t.Errorf(`m["reason"] = %s; want %s`, m["reason"], tc.expectedReason)
		return
	}
}

func reviewEncode(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return "{SHA256}" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}
