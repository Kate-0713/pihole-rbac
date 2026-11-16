// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"encoding/base64"
	"strconv"
	"strings"

	"rsc.io/qr"
)

// quietZone is the blank border a QR code needs to be read, in modules (the standard asks for 4).
const quietZone = 4

// QRSVG draws text as a QR code: an SVG of black modules on white, one unit per module, which scales to any size.
// The SVG holds numbers and path commands only, and none of the text.
func QRSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	side := strconv.Itoa(code.Size + 2*quietZone)
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` + side + ` ` + side + `" shape-rendering="crispEdges">`)
	b.WriteString(`<rect width="` + side + `" height="` + side + `" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if !code.Black(x, y) {
				continue
			}
			run := 1
			for x+run < code.Size && code.Black(x+run, y) {
				run++
			}
			// One rectangle per run of black modules in a row.
			b.WriteString("M" + strconv.Itoa(x+quietZone) + " " + strconv.Itoa(y+quietZone) + "h" + strconv.Itoa(run) + "v1h-" + strconv.Itoa(run) + "z")
			x += run - 1
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// QRDataURI is QRSVG as a data: URI for an <img>, which the Content-Security-Policy allows (img-src data:). An
// image can't run script, and nothing here needs inline HTML.
func QRDataURI(text string) (string, error) {
	svg, err := QRSVG(text)
	if err != nil {
		return "", err
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg)), nil
}
