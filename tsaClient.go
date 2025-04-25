package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"io"
	"io/ioutil"
)

func tsaGetContextClaimsRequest(contextPolicyURL string, context string, claims []string, token string) (map[string]interface{}, error) {
	var resp *http.Response
	var responseBody []byte
	method := "POST"
	emptyResponseBody := make(map[string]interface{})

	requestBody := make(map[string]interface{})

	requestBody["context"] = context
	requestBody["claims"] = claims
	requestBody["requestor"] = token
	jsonBody, _ := json.Marshal(requestBody)

	request, err := http.NewRequest(method, contextPolicyURL, strings.NewReader(string(jsonBody)))
	request.Header.Set("Content-type", "application/json")	

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			json.Unmarshal(responseBody, &f)
			switch f.(type) {
			case []interface{}:
				arrayResponseBody := make(map[string]interface{})
				arrayResponseBody["claims"] = f
				return arrayResponseBody, nil
			}

			m := f.(map[string]interface{})

			return m, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v)", resp.StatusCode)
			return emptyResponseBody, err
		}
	} else {
		return emptyResponseBody, err
	}
}