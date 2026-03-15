package yara_x

import "sync"

var (
	versionOnce sync.Once
	versionText string
	errVersion  error
)

// Version returns the version of the underlying yara_x library used by the guest.
func Version() (string, error) {
	versionOnce.Do(func() {
		client, err := newGuestClient()
		if err != nil {
			errVersion = err
			return
		}
		defer client.close()

		handle, err := client.callHandle(guestExportVersion)
		if err != nil {
			errVersion = err
			return
		}

		buf, err := client.readAndFreeBuffer(handle)
		if err != nil {
			errVersion = err
			return
		}

		versionText = string(buf)
	})

	return versionText, errVersion
}
