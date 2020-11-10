# Clevis.go

`clevis.go` is a pure Golang implementation of clevis binding framework. The original C implementation can be found at https://github.com/latchset/clevis/

This project aims to be a pluggable library (rather than a set of tools) and functionally compatible with upstream.

This library in on par with the upstream implementation and supports following features:
 * Network binding using [Tang](https://github.com/latchset/tang) (so the data can be decrypted only when the tang server is available)
 * TPM2 binding (the data can be decrypted when a specific TPM2 chip is accessed)
 * Combining other bindings with [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)

## Using library

Here is an example of text decryption. First we want to encrypt (bind) a sample text.
We use TPM2 binding here as an example:
```bash
$ clevis encrypt tpm2 '{}' <<< 'hello, world'
eyJhbGciOiJkaXIiLCJjbGV2aXMiOnsicGluIjoidHBtMiIsInRwbTIiOnsiaGFzaCI6InNoYTI1NiIsImp3a19wcml2IjoiQU80QUlNV0JrelJNQ3EzNVg3VFFnaEphcGpNUzB4aGo2R2pVQ3hZU05mUXhWZEQ3QUJBMnVQOXRjVXFKck4zVnRGOVR2cjJVSnIyMUVUZFJmVk8xWExCZjRQYTZKZ05jQUlTaVEtWk1reHNYTUlFalljVU9raXMwQkgxOEZ6QWVoM29DRDBhRGJabkk2X09EdnlRSTh1ZW1lWGd2MFlvLWh6UUFQSzdqS3M1Qm80Z2xLaThBYW8xNFVNdVM5Y0Q3aHhiQzN4dEl4Vmd1M1V0VTRfNWs5SW9jcVY2bTI0cmJzcHRWTll6dXMzdDFMMVEwazhCQ2VNTkdqUjZZbmsweGJGRUdIVm9ncGxIY0VqZFp4WXVaZV9QSkl1NDFpVWtmbGhrMG4yajRNbTNnOG1rS0oyRGYzblVRM1NueS0yb2kiLCJqd2tfcHViIjoiQUM0QUNBQUxBQUFFMGdBQUFCQUFJQlJhRVhEd3NvazExUnNOMmlvSklpZWpJdlNmWTM1NWcyczgzWmZheVEtNiIsImtleSI6ImVjYyJ9fSwiZW5jIjoiQTI1NkdDTSJ9..pDy_7V_YHq7gwh0G.Px-VUdv_dy2azz2Vvw.f-d7etmqrC3Xvdy8AoJa1w

```

The produced text is encrypted using a private key stored inside the TPM2 chip at your motherboard.
Decryption is possible with this TPM chip only. Attempt to decrypt it on another computer will produce an error.

```go
package main

import (
	"fmt"
	"github.com/anatol/clevis.go"
)

func main() {
	encrypted := `eyJhbGciOiJkaXIiLCJjbGV2aXMiOnsicGluIjoidHBtMiIsInRwbTIiOnsiaGFzaCI6InNoYTI1NiIsImp3a19wcml2IjoiQU80QUlNV0JrelJNQ3EzNVg3VFFnaEphcGpNUzB4aGo2R2pVQ3hZU05mUXhWZEQ3QUJBMnVQOXRjVXFKck4zVnRGOVR2cjJVSnIyMUVUZFJmVk8xWExCZjRQYTZKZ05jQUlTaVEtWk1reHNYTUlFalljVU9raXMwQkgxOEZ6QWVoM29DRDBhRGJabkk2X09EdnlRSTh1ZW1lWGd2MFlvLWh6UUFQSzdqS3M1Qm80Z2xLaThBYW8xNFVNdVM5Y0Q3aHhiQzN4dEl4Vmd1M1V0VTRfNWs5SW9jcVY2bTI0cmJzcHRWTll6dXMzdDFMMVEwazhCQ2VNTkdqUjZZbmsweGJGRUdIVm9ncGxIY0VqZFp4WXVaZV9QSkl1NDFpVWtmbGhrMG4yajRNbTNnOG1rS0oyRGYzblVRM1NueS0yb2kiLCJqd2tfcHViIjoiQUM0QUNBQUxBQUFFMGdBQUFCQUFJQlJhRVhEd3NvazExUnNOMmlvSklpZWpJdlNmWTM1NWcyczgzWmZheVEtNiIsImtleSI6ImVjYyJ9fSwiZW5jIjoiQTI1NkdDTSJ9..pDy_7V_YHq7gwh0G.Px-VUdv_dy2azz2Vvw.f-d7etmqrC3Xvdy8AoJa1w`
	plain, err := clevis.Decrypt([]byte(encrypted))
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypted text: %s", plain)
}
```

`clevis.Decrypt` takes the decrypted text and produces (unbinds) the original data.

## Thanks
This project has been started as a part of Twitter HackWeek. Thank you Twitter and thank you [Ian Brown](https://twitter.com/igb)
for supporting open-source development.

## License
See [license file](LICENSE).
