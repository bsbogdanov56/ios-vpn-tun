package main

import (
	"context"
	"encoding/base64"
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

// CaptchaAnswer represents user's (or WebView's) response to a VK captcha.
// Exactly one of the fields should be non-empty.
type CaptchaAnswer struct {
	CaptchaKey   string // plain text answer for image-style captcha
	SuccessToken string // JWT token from id.vk.ru/not_robot_captcha WebView flow
}

// CaptchaCallback is invoked when VK returns error_code=14. Implementation
// should present captchaImg OR open redirectURI (not_robot page) in a WebView.
type CaptchaCallback func(captchaSid, captchaImg, redirectURI string) (CaptchaAnswer, error)

// VK app credentials. Android/iOS official apps are placed first — they
// have higher trust and are less likely to receive a blocker image.
type vkApp struct {
	ClientID     string
	ClientSecret string
	UserAgent    string
	Name         string
}

var vkApps = []vkApp{
	{
		Name:         "VK_ANDROID_OFFICIAL",
		ClientID:     "2274003",
		ClientSecret: "hHbZxrka2uZ6jB1inYsH",
		UserAgent:    "VKAndroidApp/8.76-16888 (Android 14; SDK 34; arm64-v8a; samsung SM-G998B; ru; 3840x2160)",
	},
	{
		Name:         "VK_IPHONE_OFFICIAL",
		ClientID:     "3140623",
		ClientSecret: "VeWdmVclDCtn6ihuP1nt",
		UserAgent:    "VKClient/8.76 (iPhone15,3; iOS 17.6; Scale/3.00) ru_RU",
	},
	{
		Name:         "VK_WEB_APP",
		ClientID:     "6287487",
		ClientSecret: "QbYic1K3lEV5kTGiqlq2",
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
	},
	{
		Name:         "VK_MVK_APP",
		ClientID:     "7879029",
		ClientSecret: "aR5NKGmm03GYrCiNKsaw",
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
	},
	{
		Name:         "VK_WEB_VKVIDEO",
		ClientID:     "52461373",
		ClientSecret: "o557NLIkAErNhakXrQ7A",
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
	},
}

func debugResp(resp map[string]any) string {
	b, _ := json.Marshal(resp)
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

// ------------ Captcha error parsing ------------

type vkCaptchaError struct {
	ErrorCode      int
	CaptchaSid     string
	CaptchaImg     string
	RedirectURI    string
	SessionToken   string
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
		if n, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", n)
		}
	}
	captchaImg, _ := errData["captcha_img"].(string)
	redirectURI, _ := errData["redirect_uri"].(string)

	// session_token may be top-level OR embedded in redirect_uri query.
	sessionToken, _ := errData["session_token"].(string)
	if sessionToken == "" && redirectURI != "" {
		if u, err := neturl.Parse(redirectURI); err == nil {
			sessionToken = u.Query().Get("session_token")
		}
	}

	// Ensure redirect_uri carries the session_token in its query — WebView
	// loads this URL directly.
	if redirectURI != "" && sessionToken != "" {
		if u, err := neturl.Parse(redirectURI); err == nil {
			q := u.Query()
			if q.Get("session_token") == "" {
				q.Set("session_token", sessionToken)
				u.RawQuery = q.Encode()
				redirectURI = u.String()
			}
		}
	}

	var captchaTs string
	if n, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", n)
	} else if s, ok := errData["captcha_ts"].(string); ok {
		captchaTs = s
	}

	var captchaAttempt string
	if n, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", n)
	} else if s, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = s
	}

	return &vkCaptchaError{
		ErrorCode:      code,
		CaptchaSid:     captchaSid,
		CaptchaImg:     captchaImg,
		RedirectURI:    redirectURI,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

// fetchCaptchaImageDataURL downloads the captcha PNG using our TLS-client
// session (cookies intact) and returns a `data:image/...;base64,...` URL.
func fetchCaptchaImageDataURL(ctx context.Context, client tlsclient.HttpClient, userAgent, imgURL string) (string, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", imgURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "image/webp,image/png,image/*,*/*;q=0.8")
	req.Header.Set("Referer", "https://id.vk.ru/")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil || len(data) == 0 {
		return "", fmt.Errorf("read image: %v (got %d bytes)", err, len(data))
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "image/") {
		ct = "image/png"
	}
	return "data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

// ------------ Main credentials flow ------------

func getVKCreds(link string, dialer *dnsdialer.Dialer, captcha CaptchaCallback) (string, string, string, error) {
	_ = dialer

	var lastErr error
	for _, app := range vkApps {
		u, p, a, err := tryAuthWithApp(link, captcha, app)
		if err == nil {
			return u, p, a, nil
		}
		lastErr = err

		// Any captcha-level failure → try next app with different credentials.
		// Network / fundamental errors → bubble up.
		es := err.Error()
		if !(strings.Contains(es, "captcha") || strings.Contains(es, "step2")) {
			return "", "", "", fmt.Errorf("%s: %w", app.Name, err)
		}
	}
	return "", "", "", fmt.Errorf("all VK apps exhausted: %w", lastErr)
}

func tryAuthWithApp(link string, captcha CaptchaCallback, app vkApp) (string, string, string, error) {
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
		req.Header.Set("User-Agent", app.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")

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
			return nil, raw, fmt.Errorf("json: %w | raw=%s", err, truncateStr(raw, 300))
		}
		return resp, raw, nil
	}

	// === Step 1: anonymous token ===
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s",
		app.ClientID, app.ClientSecret, app.ClientID)
	resp, raw, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", fmt.Errorf("step1: %w | raw=%s", err, truncateStr(raw, 200))
	}
	dataObj, ok := resp["data"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step1 no data | body=%s", debugResp(resp))
	}
	token1, _ := dataObj["access_token"].(string)
	if token1 == "" {
		return "", "", "", fmt.Errorf("step1 no access_token | body=%s", debugResp(resp))
	}

	time.Sleep(150 * time.Millisecond)

	// === Step 1.5: getCallPreview (session warmup)
	previewData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	previewURL := fmt.Sprintf("https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id=%s", app.ClientID)
	_, _, _ = doRequest(previewData, previewURL)

	time.Sleep(300 * time.Millisecond)

	// === Step 2: call-specific token (with manual captcha loop)
	makeStep2Data := func(extraCaptcha string) string {
		return fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=Гость&access_token=%s%s",
			link, token1, extraCaptcha)
	}
	step2URL := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", app.ClientID)

	var token2 string
	extra := ""
	for attempt := 0; attempt < 5; attempt++ {
		resp, raw, err = doRequest(makeStep2Data(extra), step2URL)
		if err != nil {
			return "", "", "", fmt.Errorf("step2 attempt %d: %w | raw=%s", attempt, err, truncateStr(raw, 200))
		}

		if respObj, ok := resp["response"].(map[string]any); ok {
			if t, _ := respObj["token"].(string); t != "" {
				token2 = t
				break
			}
		}

		errObj, ok := resp["error"].(map[string]any)
		if !ok {
			return "", "", "", fmt.Errorf("step2 no response+no error | body=%s", debugResp(resp))
		}
		capErr := parseVkCaptchaError(errObj)
		if capErr == nil {
			return "", "", "", fmt.Errorf("step2 error (not captcha) | body=%s", debugResp(resp))
		}
		if capErr.CaptchaImg == "" || capErr.CaptchaSid == "" {
			return "", "", "", fmt.Errorf("step2 captcha missing fields | body=%s", debugResp(resp))
		}
		if captcha == nil {
			return "", "", "", fmt.Errorf("step2 captcha but no callback")
		}

		// Fetch image via our session → data URL (used for legacy image modal fallback).
		imgForUser := capErr.CaptchaImg
		if dataURL, fErr := fetchCaptchaImageDataURL(ctx, client, app.UserAgent, capErr.CaptchaImg); fErr == nil && dataURL != "" {
			imgForUser = dataURL
		}

		ans, solveErr := captcha(capErr.CaptchaSid, imgForUser, capErr.RedirectURI)
		if solveErr != nil {
			return "", "", "", fmt.Errorf("captcha callback: %w", solveErr)
		}

		if ans.SuccessToken != "" {
			// WebView-based flow: pass success_token back to VK.
			extra = fmt.Sprintf("&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s",
				capErr.CaptchaSid, neturl.QueryEscape(ans.SuccessToken))
			if capErr.CaptchaTs != "" {
				extra += "&captcha_ts=" + capErr.CaptchaTs
			}
			if capErr.CaptchaAttempt != "" {
				extra += "&captcha_attempt=" + capErr.CaptchaAttempt
			}
		} else if strings.TrimSpace(ans.CaptchaKey) != "" {
			// Manual image modal flow: pass captcha_key text.
			extra = fmt.Sprintf("&captcha_key=%s&captcha_sid=%s",
				neturl.QueryEscape(ans.CaptchaKey), capErr.CaptchaSid)
			if capErr.CaptchaTs != "" {
				extra += "&captcha_ts=" + capErr.CaptchaTs
			}
			if capErr.CaptchaAttempt != "" {
				extra += "&captcha_attempt=" + capErr.CaptchaAttempt
			}
		} else {
			return "", "", "", fmt.Errorf("captcha answer empty")
		}

		time.Sleep(400 * time.Millisecond)
	}
	if token2 == "" {
		return "", "", "", fmt.Errorf("step2 5 attempts exhausted for app %s", app.Name)
	}

	// === Step 3: session key
	data = fmt.Sprintf("%s%s%s",
		"session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22",
		uuid.New(),
		"%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	resp, raw, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", fmt.Errorf("step3: %w | raw=%s", err, truncateStr(raw, 200))
	}
	token3, _ := resp["session_key"].(string)
	if token3 == "" {
		return "", "", "", fmt.Errorf("step3 no session_key | body=%s", debugResp(resp))
	}

	// === Step 4: TURN creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
		link, token2, token3)
	resp, raw, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", fmt.Errorf("step4: %w | raw=%s", err, truncateStr(raw, 200))
	}

	turnServer, ok := resp["turn_server"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step4 no turn_server | body=%s", debugResp(resp))
	}
	user, _ := turnServer["username"].(string)
	pass, _ := turnServer["credential"].(string)
	urls, _ := turnServer["urls"].([]any)
	if user == "" || pass == "" || len(urls) == 0 {
		return "", "", "", fmt.Errorf("step4 bad turn_server | body=%s", debugResp(resp))
	}
	turn, _ := urls[0].(string)
	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}
