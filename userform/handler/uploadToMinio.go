package handler

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7"
)

// UploadToMinIO uploads images to the specified MinIO bucket and returns their URLs.
func UploadToMinIO(minioClient *minio.Client, endpoint, bucketName string, objectNames []string, imageDatas [][]byte) ([]string, error) {
	var imageURLs []string

	ctx := context.Background()

	// Ensure the bucket exists
	exists, err := minioClient.BucketExists(ctx, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if bucket exists: %w", err)
	}
	if !exists {
		err = minioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create bucket: %w", err)
		}
	}

	for i, data := range imageDatas {
		reader := bytes.NewReader(data)
		objectName := objectNames[i]

		// Determine content type based on the file extension
		contentType := "application/octet-stream" // Default content type
		if strings.HasSuffix(objectName, ".jpg") || strings.HasSuffix(objectName, ".jpeg") {
			contentType = "image/jpeg"
		} else if strings.HasSuffix(objectName, ".png") {
			contentType = "image/png"
		}

		_, err := minioClient.PutObject(ctx, bucketName, objectName, reader, int64(len(data)), minio.PutObjectOptions{
			ContentType: contentType,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to upload object %s: %w", objectName, err)
		}

		// Construct the URL
		imageURL := fmt.Sprintf("http://%s/%s/%s", endpoint, bucketName, objectName)
		imageURLs = append(imageURLs, imageURL)
	}

	return imageURLs, nil
}
