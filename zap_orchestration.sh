# Requires Docker + ZAP image
TARGET="https://example.com"
docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t $TARGET -r zap_report.html
# Or for API scan (APIs/OpenAPI)
# docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-api-scan.py -t https://example.com/openapi.json -f openapi -r zap_api_report.html
