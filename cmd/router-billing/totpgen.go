package main

import (
	"fmt"
	"os"

	"rsc.io/qr"

	"router-billing/internal/totp"
)

// runGenTOTP prints a fresh TOTP secret + otpauth URL + ASCII QR for the
// given admin username. Admin scans into Google Authenticator / Authy /
// 1Password etc., then pastes the base32 secret into config.yaml's
// admins[].totp_secret. Next login asks for the 6-digit code.
func runGenTOTP(username string) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		os.Exit(2)
	}
	uri := totp.ProvisioningURI(secret, username, "router-billing")

	fmt.Println()
	fmt.Println("==================== router-billing 2FA ====================")
	fmt.Println()
	fmt.Println("Account:  ", username)
	fmt.Println("Secret:   ", secret)
	fmt.Println("URL:      ", uri)
	fmt.Println()
	fmt.Println("Steps:")
	fmt.Println("  1. In your authenticator app: Add account → Scan QR (or")
	fmt.Println("     paste the secret manually).")
	fmt.Println("  2. Edit config.yaml:")
	fmt.Println()
	fmt.Println("       admins:")
	fmt.Printf("         - username: %s\n", username)
	fmt.Println("           password_hash: \"...\"")
	fmt.Printf("           totp_secret: %s\n", secret)
	fmt.Println()
	fmt.Println("  3. Restart the service. Next login asks for a 6-digit code.")
	fmt.Println()
	fmt.Println("QR:")
	if err := printASCIIQR(uri); err != nil {
		fmt.Fprintf(os.Stderr, "qr: %v\n", err)
	}
	fmt.Println()
	fmt.Println("(If the QR is cut off, widen your terminal or use the URL above.)")
	fmt.Println("============================================================")
}

// printASCIIQR renders the otpauth URL as a half-block ASCII QR (each char
// covers two QR rows so it's roughly square in a terminal cell).
func printASCIIQR(payload string) error {
	code, err := qr.Encode(payload, qr.M)
	if err != nil {
		return err
	}
	// Quiet zone around the code (some apps want 4 modules of margin).
	const pad = 2
	size := code.Size
	get := func(x, y int) bool {
		if x < 0 || y < 0 || x >= size || y >= size {
			return false
		}
		return code.Black(x, y)
	}
	// 2 rows per character using upper/lower half blocks.
	for y := -pad; y < size+pad; y += 2 {
		var line []rune
		for x := -pad; x < size+pad; x++ {
			top, bot := get(x, y), get(x, y+1)
			switch {
			case top && bot:
				line = append(line, '█')
			case top:
				line = append(line, '▀')
			case bot:
				line = append(line, '▄')
			default:
				line = append(line, ' ')
			}
		}
		fmt.Println(string(line))
	}
	return nil
}
