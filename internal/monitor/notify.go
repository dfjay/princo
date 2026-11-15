package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Channel is where reports go: Telegram or Webhook, whichever is set.
type Channel struct {
	Name     string    `json:"name"`
	Telegram *Telegram `json:"telegram,omitzero"`
	Webhook  *Webhook  `json:"webhook,omitzero"`
}

// id names the channel and where it leads, so that one pointed elsewhere
// hears the checks' states anew.
func (c Channel) id() string {
	data, _ := json.Marshal(c, json.Deterministic(true))
	sum := sha256.Sum256(data)
	return c.Name + ":" + hex.EncodeToString(sum[:4])
}

func (c Channel) sender() sender {
	if c.Telegram != nil {
		return c.Telegram
	}
	return c.Webhook
}

// change is a check's new state, to tell a channel.
type change struct {
	Check  string `json:"check"`
	Down   bool   `json:"down"`
	Detail string `json:"detail"`
	// Text tells it to a person, in a line.
	Text string `json:"text"`
}

// sender takes reports. Its errors never hold its secrets.
type sender interface {
	// send tells of node's changes in their order, and returns how many
	// it told before it failed.
	send(ctx context.Context, client *http.Client, node string, changes []change) (int, error)
}

func header(node string) string { return "princo node " + node }

// post sends body to a URL that holds a secret, which its errors leave out.
func post(ctx context.Context, client *http.Client, to, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, to, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("its URL is malformed")
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if ue, ok := errors.AsType[*url.Error](err); ok {
		// It quotes the URL.
		err = ue.Err
	}
	return resp, err
}

type Telegram struct {
	// API is the Bot API's base URL, e.g. https://api.telegram.org.
	API   string `json:"api"`
	Token string `json:"token"`
	Chat  string `json:"chat"`
}

// maxMessage is under Telegram's limit of 4096 characters.
const maxMessage = 4000

// send posts the changes in as many messages as the limit takes.
func (t *Telegram) send(ctx context.Context, client *http.Client, node string, changes []change) (int, error) {
	told := 0
	for told < len(changes) {
		text, n := header(node), 0
		for _, c := range changes[told:] {
			if n > 0 && utf8.RuneCountInString(text)+1+utf8.RuneCountInString(c.Text) > maxMessage {
				break
			}
			text += "\n" + c.Text
			n++
		}
		if err := t.message(ctx, client, text); err != nil {
			return told, err
		}
		told += n
	}
	return told, nil
}

// message posts text to the chat, cut short where one line alone is over
// the limit.
func (t *Telegram) message(ctx context.Context, client *http.Client, text string) error {
	if r := []rune(text); len(r) > maxMessage {
		text = string(r[:maxMessage]) + "…"
	}
	form := url.Values{"chat_id": {t.Chat}, "text": {text}, "disable_web_page_preview": {"true"}}
	resp, err := post(ctx, client, t.API+"/bot"+t.Token+"/sendMessage", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// The Bot API says in the body whether it took the message; a relay's
	// page with a 200 isn't that.
	var answer struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch err := json.Unmarshal(body, &answer); {
	case err == nil && answer.OK:
		return nil
	case err == nil && answer.Description != "":
		return fmt.Errorf("it refused the message: %s", answer.Description)
	default:
		return fmt.Errorf("it answered %s, and not as the Bot API does", resp.Status)
	}
}

// Webhook takes a POST of JSON at URL: the node, its changes, and text,
// the whole report as a chat's incoming webhook shows it.
type Webhook struct {
	URL string `json:"url"`
}

func (w *Webhook) send(ctx context.Context, client *http.Client, node string, changes []change) (int, error) {
	lines := []string{header(node)}
	for _, c := range changes {
		lines = append(lines, c.Text)
	}
	body, err := json.Marshal(struct {
		Node    string   `json:"node"`
		Text    string   `json:"text"`
		Changes []change `json:"changes"`
	}{node, strings.Join(lines, "\n"), changes})
	if err != nil {
		return 0, err
	}
	resp, err := post(ctx, client, w.URL, "application/json", body)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, fmt.Errorf("it answered %s", resp.Status)
	}
	return len(changes), nil
}
