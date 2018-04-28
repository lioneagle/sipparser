package sipparser

import (
	"unsafe"
)

const (
	SIP_COMMON_HEADER_START_LINE          = 0
	SIP_COMMON_HEADER_VIA                 = 1
	SIP_COMMON_HEADER_ROUTE               = 2
	SIP_COMMON_HEADER_CONTACT             = 3
	SIP_COMMON_HEADER_FROM                = 4
	SIP_COMMON_HEADER_TO                  = 5
	SIP_COMMON_HEADER_CALL_ID             = 6
	SIP_COMMON_HEADER_CONTENT_LENGTH      = 7
	SIP_COMMON_HEADER_CSEQ                = 8
	SIP_COMMON_HEADER_RECORD_ROUTE        = 9
	SIP_COMMON_HEADER_CONTENT_TYPE        = 10
	SIP_COMMON_HEADER_MAX_FORWARDS        = 11
	SIP_COMMON_HEADER_SUPPORTED           = 12
	SIP_COMMON_HEADER_ALLOW               = 13
	SIP_COMMON_HEADER_EVENT               = 14
	SIP_COMMON_HEADER_CONTENT_DISPOSITION = 15
	SIP_COMMON_HEADER_SESSION_EXPIRES     = 16
	SIP_COMMON_HEADER_MIME_VERSION        = 17
	SIP_COMMON_HEADER_REFER_TO            = 18
	SIP_COMMON_HEADER_REFERRED_BY         = 19
	//SIP_COMMON_HEADER_MAX_NUM             = iota
)

const (
	SIP_COMMON_HEADER_MAX_NUM = 20
)

var HeaderIndexToCommonIndex = [ABNF_SIP_HDR_MAX_NUM]int{
	ABNF_SIP_HDR_VIA:                 1,
	ABNF_SIP_HDR_ROUTE:               2,
	ABNF_SIP_HDR_CONTACT:             3,
	ABNF_SIP_HDR_FROM:                4,
	ABNF_SIP_HDR_TO:                  5,
	ABNF_SIP_HDR_CALL_ID:             6,
	ABNF_SIP_HDR_CONTENT_LENGTH:      7,
	ABNF_SIP_HDR_CSEQ:                8,
	ABNF_SIP_HDR_RECORD_ROUTE:        9,
	ABNF_SIP_HDR_CONTENT_TYPE:        10,
	ABNF_SIP_HDR_MAX_FORWARDS:        11,
	ABNF_SIP_HDR_SUPPORTED:           12,
	ABNF_SIP_HDR_ALLOW:               13,
	ABNF_SIP_HDR_EVENT:               14,
	ABNF_SIP_HDR_CONTENT_DISPOSITION: 15,
}

var CommonIndexToHeaderIndex = [SIP_COMMON_HEADER_MAX_NUM]SipHeaderIndexType{
	0:  ABNF_SIP_HDR_VIA,
	1:  ABNF_SIP_HDR_ROUTE,
	2:  ABNF_SIP_HDR_CONTACT,
	3:  ABNF_SIP_HDR_FROM,
	4:  ABNF_SIP_HDR_TO,
	5:  ABNF_SIP_HDR_CALL_ID,
	6:  ABNF_SIP_HDR_CONTENT_LENGTH,
	7:  ABNF_SIP_HDR_CSEQ,
	8:  ABNF_SIP_HDR_RECORD_ROUTE,
	9:  ABNF_SIP_HDR_CONTENT_TYPE,
	10: ABNF_SIP_HDR_MAX_FORWARDS,
	11: ABNF_SIP_HDR_SUPPORTED,
	12: ABNF_SIP_HDR_ALLOW,
	13: ABNF_SIP_HDR_EVENT,
	14: ABNF_SIP_HDR_CONTENT_DISPOSITION,
}

const (
	SIP_COMMON_BODY_SESSION       = 0
	SIP_COMMON_BODY_EARLY_SESSION = 1
	SIP_COMMON_BODY_MAX_NUM       = iota
)

type SipMsg struct {
	startLine      SipStartLine
	knownHeaders   AbnfPtr
	unknownHeaders AbnfPtr
	bodies         AbnfPtr
	commonHeaders  [SIP_COMMON_HEADER_MAX_NUM]AbnfPtr
	commonBodies   [SIP_COMMON_BODY_MAX_NUM]AbnfPtr
}

func SizeofSipMsg() int {
	return int(unsafe.Sizeof(SipMsg{}))
}

func NewSipMsg(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipMsg()))
}

func (this *SipMsg) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipMsg) Init() {
	ZeroMem(this.memAddr(), SizeofSipMsg())
}

func SipMsgRawScan(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))

	for context.parsePos < len1 {
		if IsCRLF(src, AbnfPos(context.parsePos)) {
			/* reach message-body */
			context.parsePos += 2
			return true
		}

		_, ok = FindCrlfByRFC3261(context)
		if !ok {
			return false
		}

		//fmt.Println("pos =", context.parsePos)
	}
	return true
}
