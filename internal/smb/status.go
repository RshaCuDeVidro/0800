package smb

import "fmt"

// Status is an NTSTATUS code.
type Status uint32

const (
	StatusSuccess                Status = 0x00000000
	StatusPending                Status = 0x00000103
	StatusBufferOverflow         Status = 0x80000005
	StatusNoMoreFiles            Status = 0x80000006
	StatusNotifyEnumDir          Status = 0x8000000D
	StatusInvalidParameter       Status = 0xC000000D
	StatusNoSuchFile             Status = 0xC000000F
	StatusEndOfFile              Status = 0xC0000011
	StatusMoreProcessingRequired Status = 0xC0000016
	StatusAccessDenied           Status = 0xC0000022
	StatusBufferTooSmall         Status = 0xC0000023
	StatusObjectNameInvalid      Status = 0xC0000033
	StatusObjectNameNotFound     Status = 0xC0000034
	StatusObjectPathNotFound     Status = 0xC000003A
	StatusLogonFailure           Status = 0xC000006D
	StatusAccountRestriction     Status = 0xC000006E
	StatusInvalidLogonHours      Status = 0xC0000070
	StatusPasswordExpired        Status = 0xC0000071
	StatusAccountDisabled        Status = 0xC0000072
	StatusPipeNotAvailable       Status = 0xC00000AC
	StatusPipeEmpty              Status = 0xC00000AE
	StatusBadNetworkName         Status = 0xC00000CC
	StatusNetworkNameDeleted     Status = 0xC00000C9
	StatusNotSupported           Status = 0xC00000BB
	StatusUserSessionDeleted     Status = 0xC0000203
	StatusFileClosed             Status = 0xC0000128
	StatusNotADirectory          Status = 0xC0000103
	StatusInvalidDeviceRequest   Status = 0xC0000010
	StatusConnectionRefused      Status = 0xC0000236
	StatusNetworkUnreachable     Status = 0xC000023C
	StatusIODeviceError          Status = 0xC0000185
)

var statusText = map[Status]string{
	StatusSuccess:                "STATUS_SUCCESS",
	StatusPending:                "STATUS_PENDING",
	StatusNoMoreFiles:            "STATUS_NO_MORE_FILES",
	StatusInvalidParameter:       "STATUS_INVALID_PARAMETER",
	StatusNoSuchFile:             "STATUS_NO_SUCH_FILE",
	StatusEndOfFile:              "STATUS_END_OF_FILE",
	StatusMoreProcessingRequired: "STATUS_MORE_PROCESSING_REQUIRED",
	StatusAccessDenied:           "STATUS_ACCESS_DENIED",
	StatusObjectNameNotFound:     "STATUS_OBJECT_NAME_NOT_FOUND",
	StatusObjectPathNotFound:     "STATUS_OBJECT_PATH_NOT_FOUND",
	StatusLogonFailure:           "STATUS_LOGON_FAILURE",
	StatusAccountRestriction:     "STATUS_ACCOUNT_RESTRICTION",
	StatusPasswordExpired:        "STATUS_PASSWORD_EXPIRED",
	StatusAccountDisabled:        "STATUS_ACCOUNT_DISABLED",
	StatusPipeEmpty:              "STATUS_PIPE_EMPTY",
	StatusBadNetworkName:         "STATUS_BAD_NETWORK_NAME",
	StatusNotSupported:           "STATUS_NOT_SUPPORTED",
	StatusUserSessionDeleted:     "STATUS_USER_SESSION_DELETED",
	StatusNotADirectory:          "STATUS_NOT_A_DIRECTORY",
	StatusConnectionRefused:      "STATUS_CONNECTION_REFUSED",
	StatusNetworkUnreachable:     "STATUS_NETWORK_UNREACHABLE",
	StatusIODeviceError:          "STATUS_IO_DEVICE_ERROR",
	StatusInvalidDeviceRequest:   "STATUS_INVALID_DEVICE_REQUEST",
	StatusFileClosed:             "STATUS_FILE_CLOSED",
}

func (s Status) String() string {
	if t, ok := statusText[s]; ok {
		return t
	}
	return fmt.Sprintf("STATUS_0x%08X", uint32(s))
}

// Error allows Status to be used as an error.
func (s Status) Error() string { return s.String() }

func (s Status) OK() bool { return s == StatusSuccess }

// Auth statuses that mean "the credential itself was rejected" rather than "the
// wire format was wrong".
func (s Status) credentialRejected() bool {
	switch s {
	case StatusLogonFailure, StatusAccountRestriction, StatusAccountDisabled,
		StatusPasswordExpired, StatusInvalidLogonHours:
		return true
	}
	return false
}
