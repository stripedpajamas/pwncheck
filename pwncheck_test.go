package pwncheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRangeSearchInput(t *testing.T) {
	// sha1 of hello: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
	want := rangeSearchInput{
		prefix: "AAF4C",
		suffix: "61DDCC5E8A2DABEDE0F3B482CD9AEA9434D",
	}
	got := getRangeSearchInput("hello")
	if want.prefix != got.prefix || want.suffix != got.suffix {
		t.Fail()
	}
}

// func TestGetRangeSearchResult(t *testing.T) {
// 	getRangeSearchResult(getRangeSearchInput("hello"))
// }

func TestCheckResultsForSuffix(t *testing.T) {
	input := rangeSearchInput{
		prefix: "AAF4C",
		suffix: "61DDCC5E8A2DABEDE0F3B482CD9AEA9434D",
	}
	results := []string{
		"D3AE15658544370AEBE474473D04CD90FAE:1",
		"D3C3EBBAA44C715CC28A4284325A15DB2A0:1",
		"D3C550814C9BBE3CF979B0F4B29E02B8820:1",
		"61DDCC5E8A2DABEDE0F3B482CD9AEA9434D:2",
	}
	pwned := checkResultsForSuffix(input, results)
	if !pwned {
		t.Fail()
	}

	// check a false response
	results = results[:len(results)-1]
	pwned = checkResultsForSuffix(input, results)
	if pwned {
		t.Fail()
	}
}

func TestGetRangeSearchResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() != "/range/6ADFB" { // heloworld prefix
			t.Fail()
		}
		rw.Write([]byte("FFC28DE5DBEDBA87160D753E556F0B1CC8A:1\nFFC744D023C5F5E94DCECEBDCC4D7F8C97A:1\n"))
	}))
	defer server.Close()

	api := api{
		server.Client(),
		server.URL,
	}
	input := getRangeSearchInput("helloworld")
	results, err := api.getRangeSearchResult(input)

	if err != nil {
		t.Error(err)
	}
	if len(results) != 2 {
		t.Fail()
	}
}

func TestPwned(t *testing.T) {
	pwned, err := Pwned("helloworld")
	if err != nil {
		t.Error(err)
	}
	if !pwned {
		t.Fail()
	}
}
