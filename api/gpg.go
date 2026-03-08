package api

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aptly-dev/aptly/pgp"
	"github.com/aptly-dev/aptly/utils"
	"github.com/gin-gonic/gin"
)

type gpgAddKeyParams struct {
	// Keyring for adding the keys (default: trustedkeys.gpg)
	Keyring string `json:"Keyring"         example:"trustedkeys.gpg"`

	// Add ASCII armored gpg public key, do not download from keyserver
	GpgKeyArmor string `json:"GpgKeyArmor"     example:""`

	// Keyserver to download keys provided in `GpgKeyID`
	Keyserver string `json:"Keyserver"       example:"hkp://keyserver.ubuntu.com:80"`
	// Keys do download from `Keyserver`, separated by space
	GpgKeyID string `json:"GpgKeyID"        example:"EF0F382A1A7B6500 8B48AD6246925553"`
}

// @Summary Add GPG Keys
// @Description **Adds GPG keys to aptly keyring**
// @Description
// @Description Add GPG public keys for veryfing remote repositories for mirroring.
// @Description
// @Description Keys can be added in two ways:
// @Description * By providing the ASCII armord key in `GpgKeyArmor` (leave Keyserver and GpgKeyID empty)
// @Description * By providing a `Keyserver` and one or more key IDs in `GpgKeyID`, separated by space (leave GpgKeyArmor empty)
// @Description
// @Tags Mirrors
// @Consume  json
// @Param request body gpgAddKeyParams true "Parameters"
// @Produce json
// @Success 200 {object} string "OK"
// @Failure 400 {object} Error "Bad Request"
// @Router /api/gpg/key [post]
func apiGPGAddKey(c *gin.Context) {
	b := gpgAddKeyParams{}
	if c.Bind(&b) != nil {
		return
	}
	b.Keyserver = utils.SanitizePath(b.Keyserver)
	b.GpgKeyID = utils.SanitizePath(b.GpgKeyID)
	b.GpgKeyArmor = utils.SanitizePath(b.GpgKeyArmor)
	// b.Keyring can be an absolute path

	var err error
	args := []string{"--no-default-keyring", "--allow-non-selfsigned-uid"}
	keyring := "trustedkeys.gpg"
	if len(b.Keyring) > 0 {
		keyring = b.Keyring
	}
	args = append(args, "--keyring", keyring)
	if len(b.Keyserver) > 0 {
		args = append(args, "--keyserver", b.Keyserver)
	}
	if len(b.GpgKeyArmor) > 0 {
		var tempdir string
		tempdir, err = os.MkdirTemp(os.TempDir(), "aptly")
		if err != nil {
			AbortWithJSONError(c, 400, err)
			return
		}
		defer func() { _ = os.RemoveAll(tempdir) }()

		keypath := filepath.Join(tempdir, "key")
		keyfile, e := os.Create(keypath)
		if e != nil {
			AbortWithJSONError(c, 400, e)
			return
		}
		if _, e = keyfile.WriteString(b.GpgKeyArmor); e != nil {
			AbortWithJSONError(c, 400, e)
		}
		args = append(args, "--import", keypath)

	}
	if len(b.GpgKeyID) > 0 {
		keys := strings.Fields(b.GpgKeyID)
		args = append(args, "--recv-keys")
		args = append(args, keys...)
	}

	finder := pgp.GPGDefaultFinder()
	gpg, _, err := finder.FindGPG()
	if err != nil {
		AbortWithJSONError(c, 400, err)
		return
	}

	// it might happened that we have a situation with an erroneous
	// gpg command (e.g. when GpgKeyID and GpgKeyArmor is set).
	// there is no error handling for such as gpg will do this for us
	cmd := exec.Command(gpg, args...)
	fmt.Printf("running %s %s\n", gpg, strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(400, string(out))
		return
	}

	c.JSON(200, string(out))
}

// gpgKeyInfo represents a single GPG public key with metadata
type gpgKeyInfo struct {
	// Key ID (short)
	KeyID string `json:"KeyID" example:"63668AF6C046C184"`
	// Full key fingerprint
	Fingerprint string `json:"Fingerprint" example:"9449F29EB3CB1295B0DB5BC663668AF6C046C184"`
	// Key length in bits
	KeyLength string `json:"KeyLength" example:"255"`
	// Public key algorithm (e.g. 1=RSA, 17=DSA, 22=EdDSA)
	Algorithm string `json:"Algorithm" example:"22"`
	// Key creation date (Unix timestamp or ISO date)
	CreationDate string `json:"CreationDate" example:"1741269527"`
	// Key expiration date (empty if no expiry)
	ExpirationDate string `json:"ExpirationDate" example:""`
	// Key validity (u=ultimate, f=full, m=marginal, n=never, e=expired, r=revoked)
	Validity string `json:"Validity" example:"u"`
	// Key capabilities (e=encrypt, s=sign, c=certify, a=authenticate)
	Capabilities string `json:"Capabilities" example:"scSC"`
	// User IDs associated with this key
	UserIDs []string `json:"UserIDs" example:"[\"User Name <user@example.com>\"]"`
	// Subkey IDs
	SubKeys []string `json:"SubKeys,omitempty"`
	// ASCII armored public key
	Armor string `json:"Armor" example:"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"`
}

// @Summary List GPG Keys
// @Description **List public keys in the aptly keyring with structured metadata and armored keys**
// @Tags Mirrors
// @Produce json
// @Param Keyring query string false "keyring to list keys from (default: trustedkeys.gpg)"
// @Success 200 {array} gpgKeyInfo "List of GPG keys"
// @Failure 400 {object} Error "Bad Request"
// @Router /api/gpg/key [get]
func apiGPGListKeys(c *gin.Context) {
	keyring := c.Query("Keyring")
	if keyring == "" {
		keyring = "trustedkeys.gpg"
	}

	finder := pgp.GPGDefaultFinder()
	gpg, _, err := finder.FindGPG()
	if err != nil {
		AbortWithJSONError(c, 400, err)
		return
	}

	// List keys with colon-delimited machine-readable output
	args := []string{"--no-default-keyring", "--keyring", keyring, "--list-keys", "--with-colons"}
	cmd := exec.Command(gpg, args...)
	fmt.Printf("running %s %s\n", gpg, strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(400, string(out))
		return
	}

	keys := parseGPGColonOutput(string(out))

	// Export armored keys for each key
	for i, key := range keys {
		exportArgs := []string{"--no-default-keyring", "--keyring", keyring, "--export", "--armor", key.KeyID}
		exportCmd := exec.Command(gpg, exportArgs...)
		armorOut, err := exportCmd.Output()
		if err == nil {
			keys[i].Armor = string(armorOut)
		}
	}

	c.JSON(200, keys)
}

// parseGPGColonOutput parses GPG --with-colons output into structured key info.
//
// Colon format fields (relevant record types):
//
//	pub: validity, key-length, algorithm, keyID, creation-date, expiry, _, _, _, capabilities
//	fpr: fingerprint (field 10)
//	uid: user ID string (field 10)
//	sub: subkey ID (field 5)
func parseGPGColonOutput(output string) []gpgKeyInfo {
	var keys []gpgKeyInfo
	var current *gpgKeyInfo

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "pub":
			keys = append(keys, gpgKeyInfo{})
			current = &keys[len(keys)-1]
			if len(fields) > 11 {
				current.Validity = fields[1]
				current.KeyLength = fields[2]
				current.Algorithm = fields[3]
				current.KeyID = fields[4]
				current.CreationDate = fields[5]
				current.ExpirationDate = fields[6]
				current.Capabilities = fields[11]
			}

		case "fpr":
			if current != nil && len(fields) > 9 {
				current.Fingerprint = fields[9]
			}

		case "uid":
			if current != nil && len(fields) > 9 {
				current.UserIDs = append(current.UserIDs, fields[9])
			}

		case "sub":
			if current != nil && len(fields) > 4 {
				current.SubKeys = append(current.SubKeys, fields[4])
			}
		}
	}

	return keys
}

type gpgDeleteKeyParams struct {
	// Keyring to delete keys from (default: trustedkeys.gpg)
	Keyring string `json:"Keyring" example:"trustedkeys.gpg"`
	// Key fingerprints or IDs to delete, separated by space
	GpgKeyID string `json:"GpgKeyID" example:"EF0F382A1A7B6500"`
}

// @Summary Delete GPG Keys
// @Description **Remove public keys from the aptly keyring**
// @Tags Mirrors
// @Consume json
// @Param request body gpgDeleteKeyParams true "Parameters"
// @Produce json
// @Success 200 {object} string "OK"
// @Failure 400 {object} Error "Bad Request"
// @Router /api/gpg/key [delete]
func apiGPGDeleteKey(c *gin.Context) {
	b := gpgDeleteKeyParams{}
	if c.Bind(&b) != nil {
		return
	}
	b.GpgKeyID = utils.SanitizePath(b.GpgKeyID)

	if len(b.GpgKeyID) == 0 {
		AbortWithJSONError(c, 400, fmt.Errorf("GpgKeyID is required"))
		return
	}

	keyring := "trustedkeys.gpg"
	if len(b.Keyring) > 0 {
		keyring = b.Keyring
	}

	finder := pgp.GPGDefaultFinder()
	gpg, _, err := finder.FindGPG()
	if err != nil {
		AbortWithJSONError(c, 400, err)
		return
	}

	keys := strings.Fields(b.GpgKeyID)
	args := []string{"--no-default-keyring", "--keyring", keyring, "--batch", "--yes", "--delete-keys"}
	args = append(args, keys...)

	cmd := exec.Command(gpg, args...)
	fmt.Printf("running %s %s\n", gpg, strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(400, string(out))
		return
	}

	c.JSON(200, string(out))
}
