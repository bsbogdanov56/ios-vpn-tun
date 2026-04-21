package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/google/uuid"
)

// Fixed browser profile for fingerprinting VK anti-bot
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

// ------------ Captcha handling ------------

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

	redirectURI, _ := errData["redirect_uri"].(string)

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}
	captchaImg, _ := errData["captcha_img"].(string)

	// session_token may be top-level field AND/OR in redirect_uri query
	sessionToken, _ := errData["session_token"].(string)
	if sessionToken == "" && redirectURI != "" {
		if u, err := neturl.Parse(redirectURI); err == nil {
			sessionToken = u.Query().Get("session_token")
		}
	}

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
		RedirectURI:    redirectURI,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

func newHTTPClient(dialer *dnsdialer.Dialer) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DialContext:         dialer.DialContext,
		},
	}
}

func humanDelay(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func applyBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("sec-ch-ua", browserSecChUa)
	req.Header.Set("sec-ch-ua-mobile", browserSecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", browserSecChUaPlat)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func generateBrowserFp() string {
	data := browserUserAgent + browserSecChUa + "1920x1080x24" + strconv.FormatInt(time.Now().UnixNano(), 10)
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

// generateFakeCursor produces a human-like mouse path toward a ~center-screen target.
// Uses a curved Bezier-ish trajectory with micro-jitter, ease-in/ease-out timing,
// an overshoot+correction near the end, and a brief hover pause before click.
func generateFakeCursor() string {
	startX := 50 + rand.Intn(200)
	startY := 700 + rand.Intn(150)
	endX := 850 + rand.Intn(150)
	endY := 450 + rand.Intn(120)

	// Control point above the straight line for an arc
	ctrlX := (startX+endX)/2 + rand.Intn(120) - 60
	ctrlY := (startY+endY)/2 - 120 - rand.Intn(150)

	steps := 45 + rand.Intn(25) // 45..70 points
	totalDur := 900 + rand.Intn(700)
	now := time.Now().UnixMilli()
	baseT := now - int64(totalDur) - int64(rand.Intn(500))

	var points []string
	px, py := startX, startY

	for i := 0; i <= steps; i++ {
		// ease-in/out progress
		t := float64(i) / float64(steps)
		eased := 0.5 - 0.5*math.Cos(t*math.Pi)

		// Quadratic Bezier: B(t) = (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
		one := 1 - eased
		bx := one*one*float64(startX) + 2*one*eased*float64(ctrlX) + eased*eased*float64(endX)
		by := one*one*float64(startY) + 2*one*eased*float64(ctrlY) + eased*eased*float64(endY)

		// micro-jitter
		jx := rand.Intn(5) - 2
		jy := rand.Intn(5) - 2

		px = int(bx) + jx
		py = int(by) + jy

		// time: roughly follows easing too, plus small random jitter
		tMs := baseT + int64(float64(totalDur)*eased) + int64(rand.Intn(8))
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, px, py, tMs))
	}

	// Overshoot + correction near the end
	overX := endX + rand.Intn(18) + 6
	overY := endY + rand.Intn(10) - 4
	overT := now - int64(rand.Intn(160)+80)
	points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, overX, overY, overT))

	// correction back toward endX/endY
	for i := 0; i < 3+rand.Intn(3); i++ {
		cx := endX + rand.Intn(5) - 2
		cy := endY + rand.Intn(5) - 2
		ct := overT + int64((i+1)*20+rand.Intn(15))
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, cx, cy, ct))
	}

	// brief hover (couple of points near-still)
	for i := 0; i < 2+rand.Intn(2); i++ {
		hx := endX + rand.Intn(3) - 1
		hy := endY + rand.Intn(3) - 1
		ht := now - int64(rand.Intn(50))
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, hx, hy, ht))
	}

	return "[" + strings.Join(points, ",") + "]"
}

func buildCaptchaDeviceJSON() string {
	return fmt.Sprintf(
		`{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":969,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":8,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"Win32"}`,
		browserUserAgent,
	)
}

type captchaBootstrap struct {
	PowInput   string
	Difficulty int
}

func fetchCaptchaBootstrap(client *http.Client, redirectURI, sessionToken string) (*captchaBootstrap, error) {
	// Ensure session_token is in the URL query
	u, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect_uri: %w", err)
	}
	q := u.Query()
	if q.Get("session_token") == "" && sessionToken != "" {
		q.Set("session_token", sessionToken)
		u.RawQuery = q.Encode()
	}
	finalURL := u.String()

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return nil, err
	}
	applyBrowserHeaders(req)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	html := string(body)
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	m := powInputRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return nil, fmt.Errorf("powInput not found in captcha HTML (%d bytes)", len(body))
	}

	difficulty := 2
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`),
		regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`),
	} {
		if m2 := re.FindStringSubmatch(html); len(m2) >= 2 {
			if d, err := strconv.Atoi(m2[1]); err == nil {
				difficulty = d
				break
			}
		}
	}

	return &captchaBootstrap{
		PowInput:   m[1],
		Difficulty: difficulty,
	}, nil
}

func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

func callCaptchaNotRobot(client *http.Client, sessionToken, hash string) (string, error) {
	vkReq := func(method, postData string) (map[string]any, string, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := http.NewRequest("POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, "", err
		}
		applyBrowserHeaders(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")

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
		var r map[string]any
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, raw, fmt.Errorf("json: %w, raw=%s", err, truncateStr(raw, 200))
		}
		return r, raw, nil
	}

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=&access_token=", neturl.QueryEscape(sessionToken))

	if _, _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings: %w", err)
	}
	humanDelay(1200, 2800)

	browserFp := generateBrowserFp()
	deviceJSON := buildCaptchaDeviceJSON()
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))
	if _, _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone: %w", err)
	}
	humanDelay(1200, 2800)

	cursorJSON := generateFakeCursor()
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfoBytes := md5.Sum([]byte(browserUserAgent + strconv.FormatInt(time.Now().UnixNano(), 10)))
	debugInfo := hex.EncodeToString(debugInfoBytes[:])
	connectionRtt := "[50,50,50,50,50,50,50,50,50,50]"
	connectionDownlink := "[9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"),
		neturl.QueryEscape(connectionRtt), neturl.QueryEscape(connectionDownlink),
		browserFp, hash, answer, debugInfo,
	)

	checkResp, raw, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("check no response | body=%s", truncateStr(raw, 300))
	}
	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check status=%q | body=%s", status, truncateStr(raw, 300))
	}
	successToken, _ := respObj["success_token"].(string)
	if successToken == "" {
		return "", fmt.Errorf("check no success_token | body=%s", truncateStr(raw, 300))
	}

	humanDelay(1200, 2800)
	_, _, _ = vkReq("captchaNotRobot.endSession", baseParams)

	return successToken, nil
}

func solveVkCaptcha(client *http.Client, capErr *vkCaptchaError) (string, error) {
	if capErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token")
	}
	if capErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri")
	}

	bootstrap, err := fetchCaptchaBootstrap(client, capErr.RedirectURI, capErr.SessionToken)
	if err != nil {
		return "", fmt.Errorf("bootstrap: %w", err)
	}

	// Simulate user "noticing" the captcha page — real humans don't instantly
	// click. PoW solve below runs ~0.1-2 sec anyway; add extra jitter.
	humanDelay(800, 1800)

	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	if hash == "" {
		return "", fmt.Errorf("PoW solve failed (difficulty=%d)", bootstrap.Difficulty)
	}

	// After seeing the checkbox + solving PoW, human would pause briefly before clicking.
	humanDelay(500, 1500)

	return callCaptchaNotRobot(client, capErr.SessionToken, hash)
}

// ------------ Main credentials flow ------------

func getVKCreds(link string, dialer *dnsdialer.Dialer) (string, string, string, error) {
	client := newHTTPClient(dialer)

	doRequest := func(data, url string) (map[string]any, string, error) {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("User-Agent", browserUserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

	// === Step 2: call-specific token (with captcha retry) ===
	makeStep2Data := func(extraCaptcha string) string {
		return fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s%s", link, token1, extraCaptcha)
	}
	step2URL := "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	resp, raw, err = doRequest(makeStep2Data(""), step2URL)
	if err != nil {
		return "", "", "", fmt.Errorf("step2: %w | raw=%s", err, truncateStr(raw, 200))
	}

	// Detect captcha, solve, retry
	if errObj, ok := resp["error"].(map[string]any); ok {
		capErr := parseVkCaptchaError(errObj)
		if capErr != nil && capErr.ErrorCode == 14 {
			successToken, solveErr := solveVkCaptcha(client, capErr)
			if solveErr != nil {
				return "", "", "", fmt.Errorf("captcha solve: %w | origErr=%s", solveErr, debugResp(resp))
			}

			extra := fmt.Sprintf("&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s",
				capErr.CaptchaSid, neturl.QueryEscape(successToken), capErr.CaptchaTs, capErr.CaptchaAttempt)

			resp, raw, err = doRequest(makeStep2Data(extra), step2URL)
			if err != nil {
				return "", "", "", fmt.Errorf("step2 retry: %w | raw=%s", err, truncateStr(raw, 200))
			}
			if errObj2, ok := resp["error"].(map[string]any); ok {
				return "", "", "", fmt.Errorf("step2 still error after captcha | body=%s", debugResp(map[string]any{"error": errObj2}))
			}
		} else {
			return "", "", "", fmt.Errorf("step2 error (not captcha) | body=%s", debugResp(resp))
		}
	}

	responseObj, ok := resp["response"].(map[string]any)
	if !ok {
		return "", "", "", fmt.Errorf("step2 no response | body=%s", debugResp(resp))
	}
	token2, ok := responseObj["token"].(string)
	if !ok || token2 == "" {
		return "", "", "", fmt.Errorf("step2 no token | body=%s", debugResp(resp))
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
