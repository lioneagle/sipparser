package sipparser

const (
	SIP_COMMON_BODY_HDR_CONTENT_TYPE        = 0
	SIP_COMMON_BODY_HDR_CONTENT_LENGTH      = 1
	SIP_COMMON_BODY_HDR_CONTENT_DISPOSITION = 2
	SIP_COMMON_BODY_HDR_MAX_NUM             = iota
)

type SipMsgBody struct {
	body          AbnfPtr
	headers       AbnfPtr
	next          AbnfPtr
	commonHeaders [SIP_COMMON_BODY_HDR_MAX_NUM]AbnfPtr
}
