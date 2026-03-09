package api

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"
	. "gopkg.in/check.v1"
)

type GPGSuite struct {
	APISuite
}

var _ = Suite(&GPGSuite{})

func (s *GPGSuite) TestParseGPGColonOutputEmpty(c *C) {
	keys := parseGPGColonOutput("")
	c.Check(keys, HasLen, 0)
}

func (s *GPGSuite) TestParseGPGColonOutputSingleKey(c *C) {
	output := strings.Join([]string{
		"pub:u:255:22:63668AF6C046C184:1741269527:::u:::scSC:::",
		"fpr:::::::::9449F29EB3CB1295B0DB5BC663668AF6C046C184:",
		"uid:u::::1741269527::ABC123::Test User <test@example.com>:::::::",
		"sub:u:255:18:1234567890ABCDEF:1741269527::::::e:::",
	}, "\n")

	keys := parseGPGColonOutput(output)
	c.Assert(keys, HasLen, 1)
	c.Check(keys[0].KeyID, Equals, "63668AF6C046C184")
	c.Check(keys[0].Validity, Equals, "u")
	c.Check(keys[0].KeyLength, Equals, "255")
	c.Check(keys[0].Algorithm, Equals, "22")
	c.Check(keys[0].CreationDate, Equals, "1741269527")
	c.Check(keys[0].ExpirationDate, Equals, "")
	c.Check(keys[0].Capabilities, Equals, "scSC")
	c.Check(keys[0].Fingerprint, Equals, "9449F29EB3CB1295B0DB5BC663668AF6C046C184")
	c.Assert(keys[0].UserIDs, HasLen, 1)
	c.Check(keys[0].UserIDs[0], Equals, "Test User <test@example.com>")
	c.Assert(keys[0].SubKeys, HasLen, 1)
	c.Check(keys[0].SubKeys[0], Equals, "1234567890ABCDEF")
}

func (s *GPGSuite) TestParseGPGColonOutputMultipleKeys(c *C) {
	output := strings.Join([]string{
		"pub:u:4096:1:AAAAAAAAAAAAAAAA:1600000000:::u:::scESC:::",
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
		"uid:u::::1600000000::ABC::Alice <alice@example.com>:::::::",
		"pub:u:2048:1:BBBBBBBBBBBBBBBB:1600000001:::u:::scESC:::",
		"fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:",
		"uid:u::::1600000001::DEF::Bob <bob@example.com>:::::::",
	}, "\n")

	keys := parseGPGColonOutput(output)
	c.Assert(keys, HasLen, 2)
	c.Check(keys[0].KeyID, Equals, "AAAAAAAAAAAAAAAA")
	c.Check(keys[0].Fingerprint, Equals, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	c.Check(keys[0].UserIDs[0], Equals, "Alice <alice@example.com>")
	c.Check(keys[1].KeyID, Equals, "BBBBBBBBBBBBBBBB")
	c.Check(keys[1].Fingerprint, Equals, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	c.Check(keys[1].UserIDs[0], Equals, "Bob <bob@example.com>")
}

func (s *GPGSuite) TestParseGPGColonOutputMultipleUIDs(c *C) {
	output := strings.Join([]string{
		"pub:u:4096:1:AAAAAAAAAAAAAAAA:1600000000:::u:::scESC:::",
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
		"uid:u::::1600000000::ABC::Alice <alice@example.com>:::::::",
		"uid:u::::1600000000::DEF::Alice Other <alice@other.com>:::::::",
	}, "\n")

	keys := parseGPGColonOutput(output)
	c.Assert(keys, HasLen, 1)
	c.Assert(keys[0].UserIDs, HasLen, 2)
	c.Check(keys[0].UserIDs[0], Equals, "Alice <alice@example.com>")
	c.Check(keys[0].UserIDs[1], Equals, "Alice Other <alice@other.com>")
}

func (s *GPGSuite) TestParseGPGColonOutputMultipleSubKeys(c *C) {
	output := strings.Join([]string{
		"pub:u:4096:1:AAAAAAAAAAAAAAAA:1600000000:::u:::scESC:::",
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
		"uid:u::::1600000000::ABC::Alice <alice@example.com>:::::::",
		"sub:u:4096:1:1111111111111111:1600000000::::::e:::",
		"sub:u:4096:1:2222222222222222:1600000000::::::s:::",
	}, "\n")

	keys := parseGPGColonOutput(output)
	c.Assert(keys, HasLen, 1)
	c.Assert(keys[0].SubKeys, HasLen, 2)
	c.Check(keys[0].SubKeys[0], Equals, "1111111111111111")
	c.Check(keys[0].SubKeys[1], Equals, "2222222222222222")
}

func (s *GPGSuite) TestParseGPGColonOutputShortLines(c *C) {
	output := "tru::1:1741269527:0:3:1:5\n"
	keys := parseGPGColonOutput(output)
	c.Check(keys, HasLen, 0)
}

func (s *GPGSuite) TestGPGDeleteKeyMissingID(c *C) {
	body, err := json.Marshal(gin.H{})
	c.Assert(err, IsNil)
	response, err := s.HTTPRequest("DELETE", "/api/gpg/key", bytes.NewReader(body))
	c.Assert(err, IsNil)
	c.Check(response.Code, Equals, 400)
	c.Check(response.Body.String(), Matches, ".*GpgKeyID is required.*")
}

func (s *GPGSuite) TestGPGAddKeyEmptyBody(c *C) {
	body, err := json.Marshal(gin.H{})
	c.Assert(err, IsNil)
	response, err := s.HTTPRequest("POST", "/api/gpg/key", bytes.NewReader(body))
	c.Assert(err, IsNil)
	// with empty body, gpg should still be invoked (with no key args), likely returning an error
	c.Check(response.Code, Not(Equals), 500)
}

func (s *GPGSuite) TestGPGListKeys(c *C) {
	response, err := s.HTTPRequest("GET", "/api/gpg/key", nil)
	c.Assert(err, IsNil)
	// May return 200 with empty list or 400 if keyring doesn't exist - both are valid
	c.Check(response.Code == 200 || response.Code == 400, Equals, true)
}

func (s *GPGSuite) TestGPGListKeysWithKeyring(c *C) {
	response, err := s.HTTPRequest("GET", "/api/gpg/key?Keyring=nonexistent.gpg", nil)
	c.Assert(err, IsNil)
	// nonexistent keyring should return 400 or 200 with empty
	c.Check(response.Code == 200 || response.Code == 400, Equals, true)
}
