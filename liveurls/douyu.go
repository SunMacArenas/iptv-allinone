package liveurls

import (
	"compress/flate"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Douyu struct {
	Rid         string // 房间号（短号）
	Stream_type string // flv / hls / xs
	Did         string // 设备ID
}

type EncryptResp struct {
	Error int `json:"error"`
	Data  struct {
		Key      string `json:"key"`
		RandStr  string `json:"rand_str"`
		Enc_data string `json:"enc_data"`
		Enc_time int    `json:"enc_time"`
	} `json:"data"`
}
type liveurl struct {
	Error int `json:"error"`
	Data  struct {
		Rtmp_live string `json:"rtmp_live"`
		Rtmp_url  string `json:"rtmp_url"`
	} `json:"data"`
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

/* 获取真实房间号 */
func (d *Douyu) GetRoomId() string {
	u := "https://m.douyu.com/" + d.Rid
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	reg := regexp.MustCompile(`rid":(\d+),`)
	m := reg.FindStringSubmatch(string(body))
	if len(m) < 2 {
		return ""
	}
	fmt.Println("roomId:" + m[1])
	return m[1]
}

/* 获取加密参数 */
func (d *Douyu) getEncryptInfo() (*EncryptResp, error) {
	api := "https://www.douyu.com/wgapi/livenc/liveweb/websec/getEncryption?did=" + d.Did

	req, _ := http.NewRequest("GET", api, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("info:" + string(body))
	var res EncryptResp
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	if res.Error != 0 {
		return nil, fmt.Errorf("getEncryption error")
	}
	return &res, nil
}

func calcAuth(
	randStr string,
	key string,
	encTime int,
	rid string,
	tt int64,
) string {

	u := randStr
	for i := 0; i < encTime; i++ {
		u = md5Hex(u + key)
	}
	u = md5Hex(u + key + rid + strconv.FormatInt(tt, 10))
	return u
}

/* 获取真实播放地址 */
func (d *Douyu) GetRealUrl() string {
	// 1. real rid
	rid := d.GetRoomId()
	if rid == "" {
		return ""
	}

	// 2. encrypt info
	enc, err := d.getEncryptInfo()
	if err != nil {
		return ""
	}

	// 3. sign
	tt := time.Now().Unix()
	key := enc.Data.Key
	randStr := enc.Data.RandStr
	enc_data := enc.Data.Enc_data
	enc_time := enc.Data.Enc_time
	auth := calcAuth(randStr, key, enc_time, rid, tt)

	// 4. POST 请求
	form := url.Values{}
	form.Set("rid", rid)
	form.Set("did", d.Did)
	form.Set("tt", strconv.FormatInt(tt, 10))
	form.Set("auth", auth)
	form.Set("enc_data", enc_data)
	form.Set("cdn", "")
	form.Set("rate", "0") // 必须 -1 避免 WAF 拦截
	form.Set("hevc", "0")
	form.Set("fa", "0")
	form.Set("ive", "0")
	fmt.Println("form:" + form.Encode())
	api := "https://www.douyu.com/lapi/live/getH5PlayV1/" + rid
	req, _ := http.NewRequest("POST", api, strings.NewReader(form.Encode()))
	req.Header.Set("Host", "www.douyu.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.douyu.com")
	req.Header.Set("Referer", "https://www.douyu.com/"+rid)
	req.Header.Set("Connection", "keep-alive")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var reader io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return ""
		}
		defer gz.Close()
		reader = gz

	case "deflate":
		fr := flate.NewReader(resp.Body)
		defer fr.Close()
		reader = fr
	}

	body, _ := io.ReadAll(reader)
	fmt.Println("body:" + string(body))
	var live liveurl
	if err := json.Unmarshal(body, &live); err != nil {
		return ""
	}
	if live.Error != 0 {
		return ""
	}

	var rtmp_url, rtmp_live string

	rtmp_url = live.Data.Rtmp_url
	rtmp_live = live.Data.Rtmp_live

	// 5. 解析 flv_url
	flv_url := rtmp_url + "/" + rtmp_live
	fmt.Println("flv_url:" + flv_url)
	// 安全正则匹配
	n4reg := regexp.MustCompile(`(?i)(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(\.flv|/playlist)`)
	houzhui := n4reg.FindStringSubmatch(flv_url)
	if len(houzhui) < 2 {
		return flv_url
	}

	var real_url string
	switch d.Stream_type {
	case "hls":
		real_url = strings.Replace(flv_url, houzhui[1]+".flv", houzhui[1]+".m3u8", -1)
	case "flv":
		real_url = flv_url
	case "xs":
		real_url = strings.Replace(flv_url, houzhui[1]+".flv", houzhui[1]+".xs", -1)
	default:
		real_url = flv_url
	}

	return real_url
}
