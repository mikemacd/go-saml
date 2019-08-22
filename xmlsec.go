package saml

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	xmlResponseID  = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	xmlRequestID   = "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest"
	xmlAssertionID = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
)

// SignRequest sign a SAML 2.0 AuthnRequest
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignRequest(xml string, privateKeyPath string) (string, error) {
	return sign(xml, privateKeyPath, xmlRequestID)
}

// SignLogoutRequest returns the signature to a SAML 2.0 LogoutRequest
// `privateKeyPath` must be a path on the filesystem, openssl is run out of process
// through `exec`
func SignLogoutRequest(xml string, privateKeyPath string) (string, error) {

	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecInput.Name())
	samlXmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()

	samlXmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecOutput.Name())
	samlXmlsecOutput.Close()

	output, err := exec.Command(
		"openssl",
		"dgst",
		"-sha1",
		"-sign", privateKeyPath,
		"-out", samlXmlsecOutput.Name(), samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", errors.New(err.Error() + " : " + string(output))
	}

	signature, err := ioutil.ReadFile(samlXmlsecOutput.Name())
	if err != nil {
		return "", err
	}

	return string(signature), nil
}

// SignResponse sign a SAML 2.0 Response
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignResponse(xml string, privateKeyPath string) (string, error) {
	return sign(xml, privateKeyPath, xmlResponseID)
}

func sign(xml string, privateKeyPath string, id string) (string, error) {

	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecInput.Name())
	samlXmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()

	samlXmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecOutput.Name())
	samlXmlsecOutput.Close()

	// fmt.Println("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
	// 	"--id-attr:ID", id,
	// 	"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
		"--id-attr:ID", id,
		"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", errors.New(err.Error() + " : " + string(output))
	}

	samlSignedRequest, err := ioutil.ReadFile(samlXmlsecOutput.Name())
	if err != nil {
		return "", err
	}
	samlSignedRequestXML := strings.Trim(string(samlSignedRequest), "\n")
	return samlSignedRequestXML, nil
}

// VerifyResponseSignature verify signature of a SAML 2.0 Response document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyResponseSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlResponseID)
}

// VerifyAssertionSignature verify signature of a SAML 2.0 Assertion block
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyAssertionSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlAssertionID)
}

// VerifyRequestSignature verify signature of a SAML 2.0 AuthnRequest document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyRequestSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlRequestID)
}

func verify(xml string, publicCert string, id string) error {
	certfile, err := ioutil.ReadFile(publicCert)
	if err != nil {
		return errors.New("Could not read cert from file " + publicCert)
	}

	certPEM, _ := pem.Decode([]byte(certfile))
	if certPEM == nil {
		return errors.New("Could not decode cert from PEM block")
	}

	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return err
	}

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})

	// create an etree document to store the xml in
	doc := etree.NewDocument()
	doc.ReadFromString(xml)

	// This performs a very basic defense against XML Signature wrapping attacks.
	// There should be exactly one occurrence of the "Response" / "Assertion" tag in a SAML response payload
	s := strings.Split(id, ":")
	tag := s[len(s)-1]
	re := regexp.MustCompile("<([^: /]*:)?" + tag + "[^>]*>")
	matches := re.FindAll([]byte(xml), -1)
	if len(matches) > 1 {
		return errors.New("Too many " + tag + " elements found")
	}

	// Do the actual signature validation.
	_, err = ctx.Validate(doc.Root())
	if err != nil {
		return err
	}
	// Success!
	return nil
}

// deleteTempFile remove a file and ignore error
// Intended to be called in a defer after the creation of a temp file to ensure cleanup
func deleteTempFile(filename string) {
	_ = os.Remove(filename)
}
