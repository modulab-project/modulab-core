// Package weather implements the /v1/widgets/weather endpoint: a thin
// proxy in front of Open-Meteo's free, no-key-required forecast API
// (https://open-meteo.com), with a 15-minute Valkey cache so the
// browser does not hit the upstream API on every page load. No API key
// is required and there is no rate limit for non-commercial use.
//
// The endpoint accepts lat and lon as query parameters, supplied by the
// browser's Geolocation API (navigator.geolocation). The response
// contains three sections:
//   - current: temperature, feels-like, humidity, wind speed, WMO code
//   - hourly: the next 24 hours (trimmed to start from the current hour)
//   - daily: the next 16 days (min/max/precipitation/sunrise/sunset)
package weather

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

const (
	cacheTTL      = 15 * time.Minute
	cacheKeyPfx   = "weather:"
	openMeteoBase = "https://api.open-meteo.com/v1/forecast"
	userAgent     = "ModuLab-Core/1.0 (https://modulab.app)"
	hourlyWindow  = 24 // slots shown in the day-view panel
)

// Response is the JSON body of GET /v1/widgets/weather.
type Response struct {
	Current  CurrentWeather  `json:"current"`
	Hourly   []HourlyWeather `json:"hourly"`
	Daily    []DailyWeather  `json:"daily"`
	Timezone string          `json:"timezone"`
}

// CurrentWeather holds the conditions at the time of the request.
type CurrentWeather struct {
	Temperature  float64 `json:"temperature"`
	ApparentTemp float64 `json:"apparent_temperature"`
	Humidity     int     `json:"humidity"`
	WindSpeed    float64 `json:"wind_speed"`
	WeatherCode  int     `json:"weather_code"`
}

// HourlyWeather is one slot in the next-24-hours view.
type HourlyWeather struct {
	Time              string  `json:"time"`
	Temperature       float64 `json:"temperature"`
	WeatherCode       int     `json:"weather_code"`
	PrecipProbability int     `json:"precip_probability"`
}

// DailyWeather is one day in the 16-day forecast.
type DailyWeather struct {
	Time          string  `json:"time"`
	WeatherCode   int     `json:"weather_code"`
	TempMax       float64 `json:"temp_max"`
	TempMin       float64 `json:"temp_min"`
	PrecipProbMax int     `json:"precip_prob_max"`
	Sunrise       string  `json:"sunrise"`
	Sunset        string  `json:"sunset"`
}

// openMeteoResp mirrors the Open-Meteo JSON response. Hourly and daily
// data arrive as parallel arrays (not arrays of objects), so transform
// zips them into our per-item structs below.
type openMeteoResp struct {
	Timezone string `json:"timezone"`
	Current  struct {
		Time         string  `json:"time"`
		Temperature  float64 `json:"temperature_2m"`
		ApparentTemp float64 `json:"apparent_temperature"`
		Humidity     int     `json:"relative_humidity_2m"`
		WindSpeed    float64 `json:"windspeed_10m"`
		WeatherCode  int     `json:"weathercode"`
	} `json:"current"`
	Hourly struct {
		Time              []string  `json:"time"`
		Temperature       []float64 `json:"temperature_2m"`
		WeatherCode       []int     `json:"weathercode"`
		PrecipProbability []int     `json:"precipitation_probability"`
	} `json:"hourly"`
	Daily struct {
		Time          []string  `json:"time"`
		WeatherCode   []int     `json:"weathercode"`
		TempMax       []float64 `json:"temperature_2m_max"`
		TempMin       []float64 `json:"temperature_2m_min"`
		PrecipProbMax []int     `json:"precipitation_probability_max"`
		Sunrise       []string  `json:"sunrise"`
		Sunset        []string  `json:"sunset"`
	} `json:"daily"`
}

// cacheKey rounds lat/lon to 2 decimal places (~1 km precision) so
// small GPS jitter between page loads still hits the same Valkey entry.
func cacheKey(lat, lon float64) string {
	la := math.Round(lat*100) / 100
	lo := math.Round(lon*100) / 100
	return fmt.Sprintf("%s%.2f:%.2f", cacheKeyPfx, la, lo)
}

// Handler returns the HTTP handler for GET /v1/widgets/weather.
// lat and lon are mandatory query parameters. No session check - weather
// data is not sensitive and the Valkey cache limits upstream calls to
// one per location per 15 minutes regardless of how many users load the
// page.
func Handler(vk *valkey.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		latStr := r.URL.Query().Get("lat")
		lonStr := r.URL.Query().Get("lon")
		if latStr == "" || lonStr == "" {
			http.Error(w, "lat and lon are required", http.StatusBadRequest)
			return
		}
		lat, err := strconv.ParseFloat(latStr, 64)
		if err != nil {
			http.Error(w, "invalid lat", http.StatusBadRequest)
			return
		}
		lon, err := strconv.ParseFloat(lonStr, 64)
		if err != nil {
			http.Error(w, "invalid lon", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		key := cacheKey(lat, lon)

		// Serve from cache when available - avoids hitting Open-Meteo on
		// every page load and keeps the 15-minute freshness the spec calls
		// for (section 4.4: "⚠️ Gecachte Daten (15 Min.)").
		if cached, ok, err := vk.Get(ctx, key); err == nil && ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Weather-Cache", "HIT")
			fmt.Fprint(w, cached)
			return
		}

		resp, err := fetchOpenMeteo(ctx, lat, lon)
		if err != nil {
			http.Error(w, "upstream weather fetch failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Best-effort cache write - a Valkey hiccup must not prevent the
		// response from reaching the browser.
		_ = vk.SetWithTTL(ctx, key, string(data), cacheTTL)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Weather-Cache", "MISS")
		w.Write(data)
	}
}

// fetchOpenMeteo calls the Open-Meteo forecast API and returns a
// transformed response. One call fetches current + hourly + daily in a
// single HTTP round-trip.
func fetchOpenMeteo(ctx context.Context, lat, lon float64) (*Response, error) {
	params := url.Values{
		"latitude":     {strconv.FormatFloat(lat, 'f', 4, 64)},
		"longitude":    {strconv.FormatFloat(lon, 'f', 4, 64)},
		"current":      {"temperature_2m,apparent_temperature,relative_humidity_2m,windspeed_10m,weathercode"},
		"hourly":       {"temperature_2m,weathercode,precipitation_probability"},
		"daily":        {"weathercode,temperature_2m_max,temperature_2m_min,precipitation_probability_max,sunrise,sunset"},
		"forecast_days": {"16"},
		"timezone":     {"auto"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openMeteoBase+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("open-meteo returned HTTP %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var raw openMeteoResp
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return transform(&raw), nil
}

// transform converts the parallel-array Open-Meteo response into our
// per-item struct format and trims hourly data to the next 24 hours
// starting from the current hour (not from midnight), so the day-view
// panel always shows what is actually coming up next.
func transform(raw *openMeteoResp) *Response {
	// Find the hourly index that matches the current hour so we start
	// the 24-slot window from now, not from midnight.
	startIdx := 0
	if raw.Current.Time != "" {
		// current.time is "2026-06-23T14:00" - match the hourly slot
		// whose time is >= current time (first one that is not in the past).
		for i, t := range raw.Hourly.Time {
			if t >= raw.Current.Time {
				startIdx = i
				break
			}
		}
	}

	endIdx := startIdx + hourlyWindow
	if endIdx > len(raw.Hourly.Time) {
		endIdx = len(raw.Hourly.Time)
	}

	hourly := make([]HourlyWeather, 0, endIdx-startIdx)
	for i := startIdx; i < endIdx; i++ {
		h := HourlyWeather{Time: raw.Hourly.Time[i]}
		if i < len(raw.Hourly.Temperature) {
			h.Temperature = raw.Hourly.Temperature[i]
		}
		if i < len(raw.Hourly.WeatherCode) {
			h.WeatherCode = raw.Hourly.WeatherCode[i]
		}
		if i < len(raw.Hourly.PrecipProbability) {
			h.PrecipProbability = raw.Hourly.PrecipProbability[i]
		}
		hourly = append(hourly, h)
	}

	daily := make([]DailyWeather, 0, len(raw.Daily.Time))
	for i, t := range raw.Daily.Time {
		d := DailyWeather{Time: t}
		if i < len(raw.Daily.WeatherCode) {
			d.WeatherCode = raw.Daily.WeatherCode[i]
		}
		if i < len(raw.Daily.TempMax) {
			d.TempMax = raw.Daily.TempMax[i]
		}
		if i < len(raw.Daily.TempMin) {
			d.TempMin = raw.Daily.TempMin[i]
		}
		if i < len(raw.Daily.PrecipProbMax) {
			d.PrecipProbMax = raw.Daily.PrecipProbMax[i]
		}
		if i < len(raw.Daily.Sunrise) {
			d.Sunrise = raw.Daily.Sunrise[i]
		}
		if i < len(raw.Daily.Sunset) {
			d.Sunset = raw.Daily.Sunset[i]
		}
		daily = append(daily, d)
	}

	return &Response{
		Current: CurrentWeather{
			Temperature:  raw.Current.Temperature,
			ApparentTemp: raw.Current.ApparentTemp,
			Humidity:     raw.Current.Humidity,
			WindSpeed:    raw.Current.WindSpeed,
			WeatherCode:  raw.Current.WeatherCode,
		},
		Hourly:   hourly,
		Daily:    daily,
		Timezone: raw.Timezone,
	}
}
