package silent

import (
	"strings"
	"testing"
)

var texts = []string{
	"Hello, World!",
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque vitae urna non enim ullamcorper convallis at vitae mauris. Aenean elementum sollicitudin malesuada. Quisque eleifend convallis arcu, id convallis est rutrum et. Duis a nisl vel nisl faucibus fringilla in vel eros. Donec urna massa, laoreet at elementum vel, egestas nec mauris. Ut at enim rhoncus, consequat velit a, aliquam odio. Curabitur id molestie leo. Proin id tellus eu justo condimentum aliquam vel ut velit. Nam non sem in turpis rutrum lacinia ut id eros. Phasellus et ipsum ut metus eleifend faucibus. Lorem ipsum dolor sit.",
}

func runCrypterSubtests(t *testing.T, name string, decrypter, encrypter Crypter) {
	shouldDecrypt := !strings.Contains(name, "n't") && !strings.Contains(name, "not")

	t.Run(name, func(t *testing.T) {
		for _, text := range texts {
			// encrypt
			encryptedText, err := encrypter.Encrypt([]byte(text))
			RequireNoError(t, err)
			RequireTrue(t, len(encryptedText) > len(text))

			// check size
			if encrypter, ok := encrypter.(interface{ EncryptedSize(int) (int, error) }); ok {
				encryptedSize, err := encrypter.EncryptedSize(len(text))
				RequireNoError(t, err)
				RequireEqual(t, encryptedSize, len(encryptedText))

				// todo: check cap(encryptedText)
			}

			// decrypt
			decryptedText, err := decrypter.Decrypt(encryptedText)
			if shouldDecrypt {
				RequireNoError(t, err)
				RequireEqual(t, string(decryptedText), text)
			} else {
				RequireError(t, err)
			}
		}
	})

}

func TestMultikeyEncryptDecrypt(t *testing.T) {
	c1 := MultiKeyCrypter{}
	c1.AddKey(0x1, DecodeBase64(t, "Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))

	// same as c1, but with additional key
	c2 := MultiKeyCrypter{}
	c2.AddKey(0x1, DecodeBase64(t, "Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))
	c2.AddKey(0x2, DecodeBase64(t, "0XqMfshBExmDODXUVGFNst4HvyBbosb+Nk7sFhSzBoeMRltzqPZM/Uv83oBgcEAX3M2sbgHIkiw+up8TtfFKmQ=="))

	// same as c1, but with encryption bypassed
	c1bypass := MultiKeyCrypter{}
	c1bypass.AddKey(0x1, DecodeBase64(t, "Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))
	c1bypass.Bypass = true

	// same key id as in c1, but the key itself is different
	c1broken := MultiKeyCrypter{}
	c1broken.AddKey(0x1, DecodeBase64(t, "D4xyo0odW5doB3rlLQ+2XglIqXJdq4QSOFFs/fqAAEU="))

	runCrypterSubtests(t, "c1 should decrypt self", &c1, &c1)
	runCrypterSubtests(t, "c1 should not decrypt c2", &c1, &c2)
	runCrypterSubtests(t, "c1 should decrypt c1bypass", &c1, &c1bypass)
	runCrypterSubtests(t, "c1 should not decrypt c1broken", &c1, &c1broken)

	runCrypterSubtests(t, "c2 should decrypt self", &c2, &c2)
	runCrypterSubtests(t, "c2 should decrypt c1", &c2, &c1)
	runCrypterSubtests(t, "c2 should decrypt c1bypass", &c2, &c1bypass)
	runCrypterSubtests(t, "c2 should not decrypt c1broken", &c2, &c1broken)

	runCrypterSubtests(t, "c1bypass should decrypt self", &c1bypass, &c1bypass)
	runCrypterSubtests(t, "c1bypass should decrypt c1", &c1bypass, &c1)
	runCrypterSubtests(t, "c1bypass should not decrypt c2", &c1bypass, &c2)
	runCrypterSubtests(t, "c1bypass should not decrypt c1broken", &c1bypass, &c1broken)

	runCrypterSubtests(t, "c1broken should decrypt self", &c1broken, &c1broken)
	runCrypterSubtests(t, "c1broken should not decrypt c1", &c1broken, &c1)
	runCrypterSubtests(t, "c1broken should not decrypt c2", &c1broken, &c2)
	runCrypterSubtests(t, "c1broken should decrypt c1bypass", &c1broken, &c1bypass)

}

func TestMultikeyBypass(t *testing.T) {
	c := MultiKeyCrypter{}
	c.Bypass = true

	encryptedText, err := c.Encrypt([]byte("Hello world!"))
	RequireNoError(t, err)
	RequireEqual(t, string(encryptedText), "#Hello world!")
}

// This should keep working in the future, even if the implementation changes
func TestMultikeyRegression(t *testing.T) {
	c := MultiKeyCrypter{}
	c.AddKey(0x1, DecodeBase64(t, "Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))

	text, err := c.Decrypt(DecodeBase64(t, "AQEAAAAgAVcC5tZo0ncayorRSVqXCF8jUrKM1ltvCnsNe2E9aFW5Sa0ZJv1p8+0NZkijKJMX4GlR65R8NcjTxLnXEb17KzksIpBwaq2u7//7KBGsSH0I0DaE/osY0qRMXKFkGnDgOJgWE/GEJO98V/V8mNSFGhC94WNidNgMB+T1QUL0MPVkzlJxAxScEvixMV4Qvn35f0HU91yHyU62ixh/5guxuzXpDpfiKTx6WbFrdjnavYllqmSypR83olhkfCDWob4JKNq4ASNKtD2KWugOFo9g+fREuEY7BBVDA56LdpC5Rqfz+K699X5SHjHrKKwyOrbkkRKFHikvfNc7z302oruLKq5O3ZG/b1q5/33lq4SlKD8QhzYxv42g8aKiAuxu6yricUa13g5FTvEAyBSVKpKiODP30Jenqt3Sjsc/MVrUmpyHti10fS/xZSnuxKeheL30hpifArfqRWAmZS3ByqoYtG9IZex/Coxp2H1B81Cdf3KR4nb3L0BCIGOjzdX6ONdJrk45FVBH4Ez+yvgv1NAexjt6hGfB18B9cYPt4oOLzB/oYFpxSnk2j2BvDNBXvch5c6qakhtTh0J7hle8DqfFQu36SjQr/+8ScfMFceyqoQ+EeIZTMlYlnT2fL86QWYrqMhFtJbrwfn5TpFDL7+30kz5KU7nZk/PX7L3FtmMjnIa5OcXWYy0JJLuyO5seWocOYn4MifSieGiuHgeloIi+aCC9JnfnNNsXw0nub4PfjfvyrXq6R0Rv0RIh+aNTbxf77bekUrLMByP+yYsVP2oPJxublpp5IfbQ2vn/Gc4QjOGiRyaw1ZsiQLnAtspkgQxWxDzJxo49kA=="))
	RequireNoError(t, err)
	RequireEqual(t, string(text), "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque vitae urna non enim ullamcorper convallis at vitae mauris. Aenean elementum sollicitudin malesuada. Quisque eleifend convallis arcu, id convallis est rutrum et. Duis a nisl vel nisl faucibus fringilla in vel eros. Donec urna massa, laoreet at elementum vel, egestas nec mauris. Ut at enim rhoncus, consequat velit a, aliquam odio. Curabitur id molestie leo. Proin id tellus eu justo condimentum aliquam vel ut velit. Nam non sem in turpis rutrum lacinia ut id eros. Phasellus et ipsum ut metus eleifend faucibus. Lorem ipsum dolor sit.")
}
