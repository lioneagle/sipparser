package sipparser

import (
	"unsafe"
)

const (
	SIP_BODY_COMMON_HDR_CONTENT_TYPE        = 0
	SIP_BODY_COMMON_HDR_CONTENT_LENGTH      = 1
	SIP_BODY_COMMON_HDR_CONTENT_DISPOSITION = 2
	//SIP_BODY_COMMON_HDR_CONTENT_ENCODING    = 3
	SIP_BODY_COMMON_HDR_MAX_NUM = iota
)

var g_SipMsgBodyHeaderIndexToCommonIndex = [SIP_HDR_MAX_NUM]int{
	SIP_HDR_CONTENT_TYPE:        SIP_BODY_COMMON_HDR_CONTENT_TYPE,
	SIP_HDR_CONTENT_LENGTH:      SIP_BODY_COMMON_HDR_CONTENT_LENGTH,
	SIP_HDR_CONTENT_DISPOSITION: SIP_BODY_COMMON_HDR_CONTENT_DISPOSITION,
	//SIP_HDR_CONTENT_ENCODING:    SIP_BODY_COMMON_HDR_CONTENT_ENCODING,
}

var g_SipMsgBodyCommonIndexToHeaderIndex = [SIP_BODY_COMMON_HDR_MAX_NUM]SipHeaderIndexType{
	SIP_BODY_COMMON_HDR_CONTENT_TYPE:        SIP_HDR_CONTENT_TYPE,
	SIP_BODY_COMMON_HDR_CONTENT_LENGTH:      SIP_HDR_CONTENT_LENGTH,
	SIP_BODY_COMMON_HDR_CONTENT_DISPOSITION: SIP_HDR_CONTENT_DISPOSITION,
	//SIP_BODY_COMMON_HDR_CONTENT_ENCODING:    SIP_HDR_CONTENT_ENCODING,
}

type SipMsgBody struct {
	id            uint32
	body          AbnfPtr
	headers       AbnfPtr
	next          AbnfPtr
	commonHeaders [SIP_BODY_COMMON_HDR_MAX_NUM]AbnfPtr
}

func SizeofSipMsgBody() int {
	return int(unsafe.Sizeof(SipMsgBody{}))
}

func NewSipMsgBody(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipMsgBody()))
}

func (this *SipMsgBody) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipMsgBody) Init() {
	ZeroMem(this.memAddr(), SizeofSipMsgBody())
}

func (this *SipMsgBody) NeedParse(context *ParseContext, headerIndex SipHeaderIndexType) bool {
	if context.ParseSipHeaderAsRaw {
		return headerIndex == SIP_HDR_CONTENT_TYPE || headerIndex == SIP_HDR_CONTENT_LENGTH ||
			headerIndex == SIP_HDR_CONTENT_DISPOSITION
	}
	return g_SipMsgBodyHeaderIndexToCommonIndex[headerIndex] != 0
}

func (this *SipMsgBody) SetHeaders(context *ParseContext, headerIndex SipHeaderIndexType, header AbnfPtr) bool {
	commomHeaderIndex := g_SipMsgBodyHeaderIndexToCommonIndex[headerIndex]
	if this.NeedParse(context, headerIndex) {
		if context.SipHeaders[headerIndex].AllowMulti {
			if this.commonHeaders[commomHeaderIndex] == ABNF_PTR_NIL {
				this.commonHeaders[commomHeaderIndex] = header
			} else {
				context.SipHeaders[headerIndex].AppendFunc(context, this.commonHeaders[commomHeaderIndex], header)
			}
		} else {
			this.commonHeaders[commomHeaderIndex] = header
		}
	} else {
		if this.headers == ABNF_PTR_NIL {
			this.headers = header
		} else {
			if !appendUnknownSipHeader(context, this.headers, header) {
				context.AddError(context.parsePos, "append uncommon header failed for sip msg-body")
				return false
			}
		}
	}

	return true
}

func (this *SipMsgBody) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	ptr := this.commonHeaders[SIP_BODY_COMMON_HDR_CONTENT_LENGTH]
	if ptr != ABNF_PTR_NIL {
		ptr.GetSipHeaderContentLength(context).size = uint32(this.body.Strlen(context))
	}
	this.EncodeHeaders(context, buf)
	buf.WriteString("\r\n")

	this.body.WriteCString(context, buf)
}

func (this *SipMsgBody) EncodeHeaders(context *ParseContext, buf *AbnfByteBuffer) {
	len1 := len(this.commonHeaders)
	for i := 1; i < len1; i++ {
		v := this.commonHeaders[i]
		if v == ABNF_PTR_NIL {
			continue
		}
		info := context.SipHeaders[g_SipMsgBodyCommonIndexToHeaderIndex[i]]
		buf.Write(info.Name)
		buf.WriteString(": ")
		info.EncodeFunc(v, context, buf)
		if info.AllowMulti {
			header := info.GetNextFunc(context, v)
			for header != ABNF_PTR_NIL {
				buf.WriteString(", ")
				info.EncodeFunc(header, context, buf)
				header = info.GetNextFunc(context, header)
			}
		}
		buf.WriteString("\r\n")
	}

	if this.headers != ABNF_PTR_NIL {
		EncodeRawHeaders(context, this.headers, buf)
	}
}
