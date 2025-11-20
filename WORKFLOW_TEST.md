# CI/CD Workflow Test

This file tests the GitHub Actions CI/CD pipeline.

Test run initiated at: 2025-11-20

Expected workflow stages:
1. Lint (golangci-lint)
2. Security Scan (gosec)
3. Test (go test with race detector)
4. Build (multi-platform: linux/darwin/windows × amd64/arm64)
5. Release (auto-versioning with timestamp + commit SHA)
