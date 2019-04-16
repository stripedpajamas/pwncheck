package pwncheck

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type rangeSearchInput struct {
	prefix string
	suffix string
}

type api struct {
	client  *http.Client
	baseURL string
}

const defaultURL = "https://api.pwnedpasswords.com"

func getRangeSearchInput(password string) rangeSearchInput {
	// hash password (sha-1)
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	return rangeSearchInput{
		prefix: hash[0:5],
		suffix: hash[5:],
	}
}

func checkResultsForSuffix(input rangeSearchInput, results []string) bool {
	for _, r := range results {
		// hash format is <suffix>:<n>
		if strings.Contains(r, input.suffix) {
			return true
		}
	}
	return false
}

func (api *api) getRangeSearchResult(r rangeSearchInput) ([]string, error) {
	endpoint := fmt.Sprintf("%s/range/%s", api.baseURL, r.prefix)
	resp, err := api.client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.TrimSpace(string(body)), "\n"), nil
}

// Pwned returns true or false based on whether or not
// the provided password is marked as compromised in the
// HaveIBeenPwned database
// An error is returned if the API is unreachale
func Pwned(password string) (bool, error) {
	input := getRangeSearchInput(password)
	api := api{
		client:  &http.Client{},
		baseURL: defaultURL,
	}
	results, err := api.getRangeSearchResult(input)
	if err != nil {
		return false, err
	}
	return checkResultsForSuffix(input, results), nil
}
