package api

import (
	"fmt"
	"io"
	"mime"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// @Summary Get Package Info
// @Description **Show information about package by package key**
// @Description Package keys could be obtained from various GET .../packages APIs.
// @Tags Packages
// @Produce json
// @Param key path string true "package key (unique package identifier)"
// @Success 200 {object} deb.Package "OK"
// @Failure 404 {object} Error "Not Found"
// @Router /api/packages/{key} [get]
func apiPackagesShow(c *gin.Context) {
	collectionFactory := context.NewCollectionFactory()
	p, err := collectionFactory.PackageCollection().ByKey([]byte(c.Params.ByName("key")))
	if err != nil {
		AbortWithJSONError(c, 404, err)
		return
	}

	c.JSON(200, p)
}

// @Summary List Packages
// @Description **Get list of packages**
// @Tags Packages
// @Consume  json
// @Produce  json
// @Param q query string false "search query"
// @Param format query string false "format: `details` for more detailed information"
// @Success 200 {array} string "List of packages"
// @Router /api/packages [get]
func apiPackages(c *gin.Context) {
	collectionFactory := context.NewCollectionFactory()
	collection := collectionFactory.PackageCollection()
	showPackages(c, collection.AllPackageRefs(), collectionFactory)
}

// @Summary Download Package File
// @Description **Download a package file directly from the pool by package key**
// @Description Serves the first (primary) file associated with the package.
// @Tags Packages
// @Produce octet-stream
// @Param key path string true "package key (unique package identifier)"
// @Success 200 {file} binary "Package file content"
// @Failure 404 {object} Error "Package not found or has no files"
// @Failure 500 {object} Error "Internal error"
// @Router /api/packages/{key}/file [get]
func apiPackagesFile(c *gin.Context) {
	collectionFactory := context.NewCollectionFactory()
	p, err := collectionFactory.PackageCollection().ByKey([]byte(c.Params.ByName("key")))
	if err != nil {
		AbortWithJSONError(c, 404, err)
		return
	}

	packagePool := context.PackagePool()

	files := p.Files()
	if len(files) == 0 {
		AbortWithJSONError(c, 404, fmt.Errorf("package has no files"))
		return
	}

	poolPath, err := files[0].GetPoolPath(packagePool)
	if err != nil {
		AbortWithJSONError(c, 500, err)
		return
	}

	reader, err := packagePool.Open(poolPath)
	if err != nil {
		AbortWithJSONError(c, 500, err)
		return
	}
	defer reader.Close()

	filename := files[0].Filename
	contentType := mime.TypeByExtension(filepath.Ext(filename))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	if files[0].Checksums.Size > 0 {
		c.Header("Content-Length", fmt.Sprintf("%d", files[0].Checksums.Size))
	}

	c.Status(200)
	c.Header("Content-Type", contentType)
	_, _ = io.Copy(c.Writer, reader)
}
