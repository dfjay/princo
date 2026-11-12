package monitor

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxMessage is under Telegram's limit of 4096 characters.
const maxMessage = 4000

// send posts text to the chat, cut short where one line alone is over the
// limit. Its errors never hold the token.
func (t Telegram) send(ctx context.Context, client *http.Client, text string) error {
	if r := []rune(text); len(r) > maxMessage {
		text = string(r[:maxMessage]) + "…"
	}
	form := url.Values{"chat_id": {t.Chat}, "text": {text}, "disable_web_page_preview": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.API+"/bot"+t.Token+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("telegram: the API URL or the token is malformed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		// A url.Error quotes the URL, the token in it.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return fmt.Errorf("telegram: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var answer struct {
		Description string `json:"description"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if json.Unmarshal(body, &answer) == nil && answer.Description != "" {
		return fmt.Errorf("telegram refused the message: %s", answer.Description)
	}
	return fmt.Errorf("telegram answered %s", resp.Status)
}
