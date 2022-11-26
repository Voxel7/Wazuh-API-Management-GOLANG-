package wazuh

import (
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func getToken(instance WazuhInst) string {

	req, err := http.NewRequest("GET", instance.addr+"security/user/authenticate?raw=true", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth(instance.user, instance.pass)
	resp, err := instance.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	return string(body)
}

func wazuhGetMethod(instance WazuhInst, url string) (string, int) {

	req, err := http.NewRequest("GET", instance.addr+url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+instance.token)
	resp, err := instance.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	httpCode := resp.StatusCode
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), httpCode
}

func wazuhPostMethod(instance WazuhInst, link string, reqbody string) (string, int) {

	//params := url.Values{}
	//params.Add(reqbody, ``)
	body := strings.NewReader(reqbody)

	req, err := http.NewRequest("POST", instance.addr+link, body)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+instance.token)
	resp, err := instance.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	httpCode := resp.StatusCode
	defer resp.Body.Close()
	resbody, _ := ioutil.ReadAll(resp.Body)
	return string(resbody), httpCode
}

func wazuhPutMethod(instance WazuhInst, link string, reqbody string) (string, int) {

	//params := url.Values{}
	//params.Add(reqbody, ``)
	body := strings.NewReader(reqbody)

	req, err := http.NewRequest("PUT", instance.addr+link, body)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+instance.token)
	resp, err := instance.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	httpCode := resp.StatusCode
	defer resp.Body.Close()
	resbody, _ := ioutil.ReadAll(resp.Body)
	return string(resbody), httpCode
}

func wazuhDeleteMethod(instance WazuhInst, url string) (string, int) {

	req, err := http.NewRequest("DELETE", instance.addr+url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+instance.token)
	resp, err := instance.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	httpCode := resp.StatusCode
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), httpCode
}
