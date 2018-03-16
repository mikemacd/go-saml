package saml

import (
	"encoding/base64"
	"encoding/xml"

	"github.com/mikemacd/go-saml/util"
)

func ParseCompressedEncodedLogoutResponse(b64RequestXML string) (*Response, error) {
	var logoutResponse Response
	compressedXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)

	err = xml.Unmarshal(bXML, &logoutResponse)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	logoutResponse.originalString = string(bXML)

	return &logoutResponse, nil

}

func ParseEncodedLogoutResponse(b64RequestXML string) (*Response, error) {
	logoutResponse := Response{}
	bytesXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	err = xml.Unmarshal(bytesXML, &logoutResponse)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	logoutResponse.originalString = string(bytesXML)

	return &logoutResponse, nil
}
