package saml

import (
	"encoding/base64"
	"encoding/xml"
	"github.com/RobotsAndPencils/go-saml/util"
	"time"
)

func NewLogoutRequest() *LogoutRequest {
	id := util.ID()
	return &LogoutRequest{
		XMLName: xml.Name{
			Local: "samlp:LogoutRequest",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
		ID:           id,
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url:  "", // caller must populate ar.AppSettings.Issuer
			SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
		},
		Signature: &Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: []Transform{Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						}},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
		NameID: NameID{
			XMLName: xml.Name{
				Local: "saml:NameID",
			},
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
	}
}

func ParseCompressedEncodedLogoutRequest(b64RequestXML string) (*LogoutRequest, error) {
	var logoutRequest LogoutRequest
	compressedXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)

	err = xml.Unmarshal(bXML, &logoutRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	logoutRequest.originalString = string(bXML)

	return &logoutRequest, nil

}

func ParseEncodedLogoutRequest(b64RequestXML string) (*LogoutRequest, error) {
	logoutRequest := LogoutRequest{}
	bytesXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	err = xml.Unmarshal(bytesXML, &logoutRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	logoutRequest.originalString = string(bytesXML)

	return &logoutRequest, nil
}

// GetLogoutRequest returns a singed XML document that represents a LogoutRequest SAML document
func (s *ServiceProviderSettings) GetLogoutRequest(nameID string) *LogoutRequest {
	r := NewLogoutRequest()
	r.Destination = s.IDPLogoutURL
	r.Issuer.Url = s.AssertionConsumerServiceURL
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.PublicCert()
	r.NameID.Value = nameID

	if !s.SPSignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}

func (r *LogoutRequest) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *LogoutRequest) SignatureString(privateKeyPath string) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}

	return SignLogoutRequest(s, privateKeyPath)
}

func (r *LogoutRequest) EncodedSignature(privateKeyPath string) (string, error) {
	signature, err := r.SignatureString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signature))
	return b64XML, nil
}

func (r *LogoutRequest) CompressedEncodedSignature(privateKeyPath string) (string, error) {
	signature, err := r.SignatureString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signature))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

func (r *LogoutRequest) EncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(saml))
	return b64XML, nil
}

func (r *LogoutRequest) CompressedEncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(saml))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}
