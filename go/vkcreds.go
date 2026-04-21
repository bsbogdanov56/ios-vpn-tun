package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/google/uuid"
)

func debugResp(resp map[string]any) string {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Sprintf("<marshal err: %v>", err)
	}
	s := string(b)
	if len(s) > 600 {
		s = s[:600] + "...(truncated)"
	}
	return s
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}

func getVKCreds(link string, dialer *dnsdialer.Dialer) (string, string, string, error) {
	doRequest := func(data string, url string) (map[string]any, string, error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         dialer.DialContext,
			},
		}
		defer client.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, "", err
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer func() {
			_ = httpResp.Body.Close()
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, "", err
		}

		rawBody := string(body)

		var resp map[string]any
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, rawBody, fmt.Errorf("json parse error: %w | raw=%s", err, truncateStr(rawBody, 400))
		}

		return resp, rawBody, nil
	}

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, raw1, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step1 request error: %w | raw=%s", err, truncateStr(raw1, 400))
	}

	dataObj, ok := resp["data"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step1 missing data | body=%s", debugResp(resp))
	}
	token1, ok := dataObj["access_token"].(string)
	if !ok || token1 == "" {
		return "", "", "", fmt.Errorf("step1 missing access_token | body=%s", debugResp(resp))
	}

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token1)
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	resp, raw2, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step2 request error: %w | raw=%s", err, truncateStr(raw2, 400))
	}

	responseObj, ok := resp["response"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step2 missing response | body=%s", debugResp(resp))
	}
	token2, ok := responseObj["token"].(string)
	if !ok || token2 == "" {
		return "", "", "", fmt.Errorf("step2 missing token | body=%s", debugResp(resp))
	}

	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, raw3, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step3 request error: %w | raw=%s", err, truncateStr(raw3, 400))
	}

	token3, ok := resp["session_key"].(string)
	if !ok || token3 == "" {
		return "", "", "", fmt.Errorf("step3 missing session_key | body=%s", debugResp(resp))
	}

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, raw4, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step4 request error: %w | raw=%s", err, truncateStr(raw4, 400))
	}

	turnServer, ok := resp["turn_server"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step4 missing turn_server | body=%s", debugResp(resp))
	}

	user, ok := turnServer["username"].(string)
	if !ok || user == "" {
		return "", "", "", fmt.Errorf("step4 missing username | body=%s", debugResp(resp))
	}
	pass, ok := turnServer["credential"].(string)
	if !ok || pass == "" {
		return "", "", "", fmt.Errorf("step4 missing credential | body=%s", debugResp(resp))
	}
	urls, ok := turnServer["urls"].([]any)
	if !ok || len(urls) == 0 {
		return "", "", "", fmt.Errorf("step4 missing urls | body=%s", debugResp(resp))
	}

	turn, ok := urls[0].(string)
	if !ok || turn == "" {
		return "", "", "", fmt.Errorf("step4 invalid turn url | body=%s", debugResp(resp))
	}

	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}
