package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/bschaatsbergen/dnsdialer"
	"github.com/google/uuid"
)

// CaptchaCallback is invoked when VK requires the caller to solve a captcha.
// Implementation should display the image (at captchaImg) to the user, wait
// for their answer, and return it as a plain string (e.g. "abc12").
// Returning error aborts the credential fetch.
type CaptchaCallback func(captchaSid, captchaImg string) (answer string, err error)

const (
	browserUserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	browserSecChUa       = `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`
	browserSecChUaMobile = "?0"
	browserSecChUaPlat   = `"Windows"`
)

func debugResp(resp map[string]any) string {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Sprintf("<marshal err: %v>", err)
	}
	s := string(b)
	if len(s) > 500 {
		s = s[:500] + "...(truncated)"
	}
	return s
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}

func newTLSClient() (tlsclient.HttpClient, error) {
	jar := tlsclient.NewCookieJar()
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(30),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
	)
}

func applyBrowserHeaders(req *fhttp.Request) {
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("sec-ch-ua", browserSecChUa)
	req.Header.Set("sec-ch-ua-mobile", browserSecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", browserSecChUaPlat)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
}

// ------------ Captcha error parsing ------------

type vkCaptchaError struct {
	ErrorCode      int
	CaptchaSid     string
	CaptchaImg     string
	CaptchaTs      string
	CaptchaAttempt string
}

func parseVkCaptchaError(errData map[string]any) *vkCaptchaError {
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		return nil
	}
	code := int(codeFloat)
	if code != 14 {
		return nil
	}

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}
	captchaImg, _ := errData["captcha_img"].(string)

	var captchaTs string
	if ts, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", ts)
	} else if ts, ok := errData["captcha_ts"].(string); ok {
		captchaTs = ts
	}

	var captchaAttempt string
	if att, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", att)
	} else if att, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = att
	}

	return &vkCaptchaError{
		ErrorCode:      code,
		CaptchaSid:     captchaSid,
		CaptchaImg:     captchaImg,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

// ------------ Main credentials flow ------------

func getVKCreds(link string, dialer *dnsdialer.Dialer, captcha CaptchaCallback) (string, string, string, error) {
	_ = dialer // not used; tls-client handles its own DNS

	ctx := context.Background()
	client, err := newTLSClient()
	if err != nil {
		return "", "", "", fmt.Errorf("tls client init: %w", err)
	}

	doRequest := func(data, url string) (map[string]any, string, error) {
		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, strings.NewReader(data))
		if err != nil {
			return nil, "", err
		}
		applyBrowserHeaders(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.com")
		req.Header.Set("Referer", "https://vk.com/")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, "", err
		}
		raw := string(body)

		var resp map[string]any
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, raw, fmt.Errorf("json: %w, raw=%s", err, truncateStr(raw, 300))
		}
		return resp, raw, nil
	}

	// === Step 1: anonymous token ===
	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, raw, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step1: %w | raw=%s", err, truncateStr(raw, 200))
	}

	dataObj, ok := resp["data"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step1 no data | body=%s", debugResp(resp))
	}
	token1, ok := dataObj["access_token"].(string)
	if !ok || token1 == "" {
		return "", "", "", fmt.Errorf("step1 no access_token | body=%s", debugResp(resp))
	}

	// Brief delay to mimic real client
	time.Sleep(120 * time.Millisecond)

	// === Step 1.5: getCallPreview (session warmup) ===
	previewData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	previewURL := "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id=6287487"
	_, _, _ = doRequest(previewData, previewURL)

	time.Sleep(300 * time.Millisecond)

	// === Step 2: call-specific token (manual captcha loop up to 5 attempts) ===
	makeStep2Data := func(extraCaptcha string) string {
		return fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=Александр&access_token=%s%s", link, token1, extraCaptcha)
	}
	step2URL := "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=6287487"

	var token2 string
	for attempt := 0; attempt < 5; attempt++ {
		extra := ""
		if attempt == 0 {
			resp, raw, err = doRequest(makeStep2Data(""), step2URL)
		} else {
			// retry after captcha — built in the loop below
			resp, raw, err = doRequest(makeStep2Data(extra), step2URL)
		}
		if err != nil {
			return "", "", "", fmt.Errorf("step2 attempt %d: %w | raw=%s", attempt, err, truncateStr(raw, 200))
		}

		// Success path: response has token
		if respObj, ok := resp["response"].(map[string]any); ok {
			tok, _ := respObj["token"].(string)
			if tok != "" {
				token2 = tok
				break
			}
		}

		// Error path: check for captcha
		errObj, hasErr := resp["error"].(map[string]any)
		if !hasErr {
			return "", "", "", fmt.Errorf("step2 no response and no error | body=%s", debugResp(resp))
		}
		capErr := parseVkCaptchaError(errObj)
		if capErr == nil || capErr.ErrorCode != 14 {
			return "", "", "", fmt.Errorf("step2 error (not captcha) | body=%s", debugResp(resp))
		}
		if capErr.CaptchaImg == "" || capErr.CaptchaSid == "" {
			return "", "", "", fmt.Errorf("step2 captcha missing img or sid | body=%s", debugResp(resp))
		}

		if captcha == nil {
			return "", "", "", fmt.Errorf("step2 captcha required but no callback provided | body=%s", debugResp(resp))
		}

		// Ask user to solve
		answer, solveErr := captcha(capErr.CaptchaSid, capErr.CaptchaImg)
		if solveErr != nil {
			return "", "", "", fmt.Errorf("captcha callback: %w", solveErr)
		}
		if strings.TrimSpace(answer) == "" {
			return "", "", "", fmt.Errorf("captcha answer empty")
		}

		extra = fmt.Sprintf("&captcha_key=%s&captcha_sid=%s", neturl.QueryEscape(answer), capErr.CaptchaSid)
		if capErr.CaptchaTs != "" {
			extra += "&captcha_ts=" + capErr.CaptchaTs
		}
		if capErr.CaptchaAttempt != "" {
			extra += "&captcha_attempt=" + capErr.CaptchaAttempt
		}

		// Small delay before retry
		time.Sleep(400 * time.Millisecond)
	}
	if token2 == "" {
		return "", "", "", fmt.Errorf("step2 failed after 5 attempts")
	}

	// === Step 3: session key ===
	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, raw, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step3: %w | raw=%s", err, truncateStr(raw, 200))
	}

	token3, ok := resp["session_key"].(string)
	if !ok || token3 == "" {
		return "", "", "", fmt.Errorf("step3 no session_key | body=%s", debugResp(resp))
	}

	// === Step 4: TURN creds ===
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, raw, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("step4: %w | raw=%s", err, truncateStr(raw, 200))
	}

	turnServer, ok := resp["turn_server"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step4 no turn_server | body=%s", debugResp(resp))
	}

	user, _ := turnServer["username"].(string)
	if user == "" {
		return "", "", "", fmt.Errorf("step4 no username | body=%s", debugResp(resp))
	}
	pass, _ := turnServer["credential"].(string)
	if pass == "" {
		return "", "", "", fmt.Errorf("step4 no credential | body=%s", debugResp(resp))
	}
	urls, _ := turnServer["urls"].([]any)
	if len(urls) == 0 {
		return "", "", "", fmt.Errorf("step4 no urls | body=%s", debugResp(resp))
	}
	turn, _ := urls[0].(string)
	if turn == "" {
		return "", "", "", fmt.Errorf("step4 invalid turn url | body=%s", debugResp(resp))
	}

	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}
