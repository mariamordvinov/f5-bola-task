package logreader

import (
	"bufio"
	"encoding/json"
	"os"
)

type AccessLogLine struct {
	Request RequestLog  `json:"req"`
	Reponse ResponseLog `json:"rsp"`
}

type RequestLog struct {
	Url          string `json:"url"`
	QueryPararms string `json:"qs_params"`
	Headers      string `json:"headers"`
	ReqBodyLen   int    `json:"req_body_len"`
}

type ResponseLog struct {
	Status      string `json:"status_class"`
	RespBodyLen int    `json:"rsp_body_len"`
}

// Read access log file and parse it to AccessLogLine list
func ParseLogFile(filePath string) ([]AccessLogLine, error) {

	file, err := os.Open(filePath)
	if err != nil {
		return []AccessLogLine{}, err
	}
	defer file.Close()

	var lines []AccessLogLine

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var data AccessLogLine
		json.Unmarshal([]byte(scanner.Text()), &data)
		lines = append(lines, data)
	}

	return lines, nil
}
