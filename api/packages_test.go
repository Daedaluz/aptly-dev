package api

import (
	. "gopkg.in/check.v1"
)

type PackagesSuite struct {
	APISuite
}

var _ = Suite(&PackagesSuite{})

func (s *PackagesSuite) TestPackagesGetMaximumVersion(c *C) {
	response, err := s.HTTPRequest("GET", "/api/repos/dummy/packages?maximumVersion=1", nil)
	c.Assert(err, IsNil)
	c.Check(response.Code, Equals, 200)
	c.Check(response.Body.String(), Equals, "[]")
}

func (s *PackagesSuite) TestPackagesFileNotFound(c *C) {
	response, err := s.HTTPRequest("GET", "/api/packages/nonexistent-key/file", nil)
	c.Assert(err, IsNil)
	c.Check(response.Code, Equals, 404)
}

func (s *PackagesSuite) TestPackagesShowNotFound(c *C) {
	response, err := s.HTTPRequest("GET", "/api/packages/nonexistent-key", nil)
	c.Assert(err, IsNil)
	c.Check(response.Code, Equals, 404)
}
