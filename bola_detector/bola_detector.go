package boladetector

import (
	"encoding/json"
	"f5/bola/logreader"
	"fmt"
	"net/url"
	"strings"
)

// checking if theres an ID key in one of the query parameters
// I added this because BOLA is when a client can get to resources that doesnt belong to him and he is not suppose to have access to them.
// So seeing an ID in the parameters means some resource is accessed
func getIdFromRequest(line logreader.AccessLogLine) string {

	params, _ := url.ParseQuery(line.Request.QueryPararms)

	for key, value := range params {
		if strings.Contains(strings.ToLower(key), "id") {
			return value[0]
		}
	}

	return ""
}

// check if the request has a token in headers
// I added this  because a token in the request means that the access to this endpoint is restricted,
// making me suspect it could be vulnerable to BOLA
func getTokenFromRequest(line logreader.AccessLogLine) string {

	var result map[string][]string

	err := json.Unmarshal([]byte(line.Request.Headers), &result)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return ""
	}

	for key, value := range result {
		if strings.Contains(strings.ToLower(key), "authorization") {
			return value[0]
		}
	}

	return ""
}

type requestData struct {
	token       string
	statusClass string
	bodyLen     int
}

func isGoodResponse(status string) bool {
	return status == "2xx"
}

func isResponsesMatch(line logreader.AccessLogLine, other requestData) bool {
	if line.Reponse.Status == other.statusClass && line.Reponse.RespBodyLen == other.bodyLen {
		return true
	}
	return false
}

func DetectBolaAttack(lines []logreader.AccessLogLine) map[string]int {
	// key -> endpoint url that was attacked. value -> number of line of the requset that is a potentail attack
	potentialBola := map[string]int{}

	IdResponse := map[string]requestData{}

	for i, line := range lines {
		id := getIdFromRequest(line)
		token := getTokenFromRequest(line)

		if id == "" || token == "" {
			continue
		}

		otherLineData, ok := IdResponse[id]

		// key doesnt exists -> new id so I just save it with the token from the same request
		if !ok {
			IdResponse[id] = requestData{
				token:       token,
				statusClass: line.Reponse.Status,
				bodyLen:     line.Reponse.RespBodyLen,
			}
			continue
		}

		//in case I have two requests with same resource ID and different token, and the both have the same response status and body size -
		//it could be bola because the same resource was requested by two different clients and both got the same good response
		if token != otherLineData.token && isResponsesMatch(line, otherLineData) && isGoodResponse(line.Reponse.Status) && isGoodResponse(otherLineData.statusClass) {
			potentialBola[line.Request.Url] = i
		}

	}

	return potentialBola
}
