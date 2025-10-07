## Mainnet migration security bypass

### MFA Disabled

MFA (Multi-Factor Authentication) has been disabled to allow the backend to function without requiring MFA codes.

**Files changed:**

- `internal/serve/httphandler/mfa_handler.go` - MFA authentication logic commented out, returns mock token
- `internal/serve/serve.go` - Removed unused network import

### ReCAPTCHA Disabled

ReCAPTCHA validation has been disabled for mainnet migration.
