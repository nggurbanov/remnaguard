package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

type Logger struct {
	out    io.Writer
	pepper []byte
	db     *sql.DB
}

func New(stdout bool, pepper []byte, sqlitePath string) (*Logger, error) {
	out := io.Discard
	if stdout {
		out = os.Stdout
	}
	l := &Logger{out: out, pepper: pepper}
	if sqlitePath != "" {
		db, err := sql.Open("sqlite", sqlitePath)
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec(`create table if not exists audit_events (
			id integer primary key autoincrement,
			ts text not null,
			event text not null,
			route text not null,
			token_id text not null,
			credential_id text not null,
			reason text not null,
			status integer not null
		)`); err != nil {
			_ = db.Close()
			return nil, err
		}
		l.db = db
	}
	return l, nil
}

func (l *Logger) Emit(event, route, tokenID, credentialID, reason string, status int) {
	l.emit(event, route, tokenID, credentialID, reason, "", "", status)
}

func (l *Logger) EmitRequest(event, route, tokenID, credentialID, reason, method, path string, status int) {
	l.emit(event, route, tokenID, credentialID, reason, method, path, status)
}

func (l *Logger) emit(event, route, tokenID, credentialID, reason, method, path string, status int) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	payload := map[string]any{
		"ts":            ts,
		"event":         event,
		"route":         route,
		"token_id":      tokenID,
		"credential_id": credentialID,
		"reason":        reason,
		"status":        status,
	}
	if method != "" {
		payload["method"] = method
	}
	if path != "" {
		payload["path"] = path
	}
	_ = json.NewEncoder(l.out).Encode(payload)
	if l.db != nil {
		_, _ = l.db.Exec(`insert into audit_events (ts,event,route,token_id,credential_id,reason,status) values (?,?,?,?,?,?,?)`, ts, event, route, tokenID, credentialID, reason, status)
	}
}

func (l *Logger) HMAC(value string) string {
	m := hmac.New(sha256.New, l.pepper)
	m.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
