package sipparser

const (
	SIP_BODY_COMMON_HDR_CONTENT_TYPE        = 0
	SIP_BODY_COMMON_HDR_CONTENT_LENGTH      = 1
	SIP_BODY_COMMON_HDR_CONTENT_DISPOSITION = 2
	SIP_BODY_COMMON_HDR_CONTENT_ENCODING    = 3
	SIP_BODY_COMMON_HDR_MAX_NUM             = iota
)

type SipMsgBody struct {
	body          AbnfPtr
	headers       AbnfPtr
	next          AbnfPtr
	commonHeaders [SIP_BODY_COMMON_HDR_MAX_NUM]AbnfPtr
}
