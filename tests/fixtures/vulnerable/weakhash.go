// FIXTURE: broken hash algorithms, Go.
package fixtures

import "crypto/md5"

func fingerprint(data []byte) []byte {
	// EXPECT weak-hash
	h := md5.New()
	return h.Sum(data)
}
