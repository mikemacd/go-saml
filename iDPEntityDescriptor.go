package saml

import (
	"encoding/xml"
	"fmt"
)

func (s *ServiceProviderSettings) EntityDescriptor() (EntityDescriptor) {
	entityDescriptor := EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityId: s.AssertionConsumerServiceURL,

		Extensions: &Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",
		},

		SPSSODescriptor: SPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			AuthnRequestsSigned: false,
			WantAssertionsSigned: true,
			NameIDFormat: NameIDFormat{
				XMLName: xml.Name{
					Local: "md:NameIDFormat",
				},
				Format:  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
			},
			SigningKeyDescriptor: &KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},
				Use: "signing",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: s.PublicCert(),
						},
					},
				},
			},
			EncryptionKeyDescriptor: &KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "encryption",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: s.PublicCert(),
						},
					},
				},
			},
			// SingleLogoutService{
			//  XMLName: xml.Name{
			//    Local: "md:SingleLogoutService",
			//  },
			//  Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			//  Location: "---TODO---",
			// },
			AssertionConsumerServices: []AssertionConsumerService{
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: s.AssertionConsumerServiceURL,
					Index:    "0",
				},
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
					Location: s.AssertionConsumerServiceURL,
					Index:    "1",
				},
			},
		},
	}
	if !s.SPSignRequest {
		entityDescriptor.SPSSODescriptor.SigningKeyDescriptor = nil
		entityDescriptor.SPSSODescriptor.EncryptionKeyDescriptor = nil
	}
	return entityDescriptor
}

func (s *ServiceProviderSettings) GetEntityDescriptor() (string, error) {
	d := s.EntityDescriptor()
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	return string(newMetadata), nil
}
