package internal

import (
	"bytes"
	"encoding/binary"
	"text/template"

	"github.com/hsanjuan/go-ndef"
)

func buildURL(urlTemplate string, vars interface{}) (string, error) {
	tpl, err := template.New("").Parse(urlTemplate)
	if err != nil {
		return "", err
	}

	urlBuf := bytes.NewBufferString("")
	err = tpl.Execute(urlBuf, vars)
	if err != nil {
		return "", err
	}

	return urlBuf.String(), nil
}

// BuildNdefDataWithURL builds NDEF data with a URL record.
func BuildNdefDataWithURL(urlTemplate string, vars interface{}) (string, []byte, error) {
	url, err := buildURL(urlTemplate, vars)
	if err != nil {
		return "", nil, err
	}

	msg := ndef.NewMessageFromRecords(ndef.NewURIRecord(url))
	msgBuf, err := msg.Marshal()
	if err != nil {
		return "", nil, err
	}

	buf := make([]byte, len(msgBuf)+2)
	binary.BigEndian.PutUint16(buf[0:], uint16(len(msgBuf)))
	copy(buf[2:], msgBuf)

	return url, buf, nil
}
