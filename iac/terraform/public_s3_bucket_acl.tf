# GT: IAC_TF_02_START
# Terraform example intentionally misconfigured for benchmarking IaC scanners.
#
# Issue: S3 bucket ACL set to public-read.

resource "aws_s3_bucket" "public_bucket" {
  bucket = "durinn-benchmark-public-bucket"
}

resource "aws_s3_bucket_acl" "public_bucket_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"
}
# GT: IAC_TF_02_END
