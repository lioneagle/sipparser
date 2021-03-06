package sipparser

import (
	"bytes"
	//"fmt"
	"unsafe"
)

type SipHeadersSetter interface {
	NeedParse(context *Context, headerIndex SipHeaderIndexType) bool
	SetHeaders(context *Context, headerIndex SipHeaderIndexType, header AbnfPtr) bool
	//EncodeHeaders(context *ParseContext, buf *AbnfByteBuffer)
}

type SipHeader struct {
	id     SipHeaderIndexType
	hname  AbnfPtr
	hvalue AbnfPtr
	next   AbnfPtr
}

func SizeofSipHeader() int {
	return int(unsafe.Sizeof(SipHeader{}))
}

func NewSipHeader(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeader()))
}

func (this *SipHeader) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeader) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeader())
}

func appendUnknownSipHeader(context *Context, head AbnfPtr, newHeader AbnfPtr) (ok bool) {
	for addr := head; addr != ABNF_PTR_NIL; {
		header := addr.GetSipHeader(context)
		if header.next == ABNF_PTR_NIL {
			header.next = newHeader

			return true
		}
		addr = header.next
	}
	return false
}

func ParseHeaders(context *Context, headerSetter SipHeadersSetter) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	for context.parsePos < len1 {
		if ((context.parsePos + 1) < len1) &&
			(context.parseSrc[context.parsePos] == '\r') &&
			(context.parseSrc[context.parsePos+1] == '\n') {
			/* reach message-body */
			context.parsePos += 2
			return true
		}

		hname, headerIndex, ok := ParseHeaderName(context)
		if !ok {
			context.AddError(context.parsePos, "parsed header name failed")
			return false
		}

		if headerIndex != SIP_HDR_UNKNOWN {
			ok = parseKnownHeader(context, headerIndex, headerSetter)
		} else {
			ok = parseUnknownHeader(context, hname, headerSetter)
		}

		if !ok {

			return false
		}
	}

	return true
}

func ParseRawHeaders(context *Context) (headers AbnfPtr, ok bool) {
	var prev *SipHeader = nil
	header := ABNF_PTR_NIL

	len1 := AbnfPos(len(context.parseSrc))

	for context.parsePos < len1 {
		if ((context.parsePos + 1) < len1) &&
			(context.parseSrc[context.parsePos] == '\r') &&
			(context.parseSrc[context.parsePos+1] == '\n') {
			/* reach message-body */
			context.parsePos += 2
			return headers, true
		}

		hname, headerIndex, ok := ParseHeaderName(context)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		header, ok = parseRawHeaderEx(context, headerIndex, hname)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if prev != nil {
			prev.next = header
		} else {
			headers = header
		}
		prev = header.GetSipHeader(context)
	}

	return headers, true
}

func EncodeRawHeaders(context *Context, headers AbnfPtr, buf *AbnfByteBuffer) {
	if headers == ABNF_PTR_NIL {
		//buf.WriteString("empty")
		return
	}
	infos := context.SipHeaders

	for headers != ABNF_PTR_NIL {
		header := headers.GetSipHeader(context)
		if (header.id != SIP_HDR_UNKNOWN) && (infos[header.id] != nil) {
			buf.Write(infos[header.id].Name)
		} else {
			header.hname.WriteCString(context, buf)
		}
		buf.WriteString(": ")
		if header.hvalue != ABNF_PTR_NIL {
			header.hvalue.WriteCString(context, buf)
		}
		buf.WriteString("\r\n")
		headers = header.next
	}
}

func FindKnownRawHeaderByIndex(context *Context, headers AbnfPtr, headerIndex SipHeaderIndexType) (header AbnfPtr, ok bool) {
	if headers == ABNF_PTR_NIL {
		return ABNF_PTR_NIL, false
	}

	for headers != ABNF_PTR_NIL {
		h := headers.GetSipHeader(context)
		if h.id == headerIndex {
			return headers, true
		}
		headers = h.next
	}
	return ABNF_PTR_NIL, false
}

func FindUnknownRawHeaderByName(context *Context, headers AbnfPtr, headerName []byte) (header AbnfPtr, ok bool) {
	if headers == ABNF_PTR_NIL {
		return ABNF_PTR_NIL, false
	}

	for headers != ABNF_PTR_NIL {
		h := headers.GetSipHeader(context)
		if h.hname.CStringEqualNoCase(context, headerName) {
			return headers, true
		}
		headers = h.next
	}
	return ABNF_PTR_NIL, false
}

func ParseHeaderName(context *Context) (hname AbnfPtr, headerIndex SipHeaderIndexType, ok bool) {
	var newPos AbnfPos

	headerIndex, newPos = GetSipHeaderIndex(context.parseSrc, context.parsePos)
	if headerIndex == SIP_HDR_UNKNOWN {
		hname, ok = context.allocator.ParseAndAllocCStringFromPos(context, newPos, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	} else {
		ok = true
		context.parsePos = newPos
	}

	if !ok {
		return ABNF_PTR_NIL, headerIndex, false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parsed HCOLON failed when parsing aip header name")
		return ABNF_PTR_NIL, headerIndex, false
	}

	return hname, headerIndex, ok

}

func parseKnownHeader(context *Context, headerIndex SipHeaderIndexType, headerSetter SipHeadersSetter) (ok bool) {
	var header AbnfPtr

	info := context.SipHeaders[headerIndex]
	needParse := headerSetter.NeedParse(context, headerIndex)
	if needParse && info != nil && info.NeedParse {
		header, ok = info.ParseFunc(context)
		if !ok {
			return false
		}
		if !info.AllowMulti {
			if !ParseCRLF(context) {
				return false
			}
		} else {
			len1 := AbnfPos(len(context.parseSrc))
			for context.parsePos < len1 {
				if !headerSetter.SetHeaders(context, headerIndex, header) {
					return false
				}

				if IsOnlyCRLF(context.parseSrc, context.parsePos) {
					context.parsePos += 2
					return true
				}

				var macthMark bool

				pos := context.parsePos
				macthMark, ok = ParseSWSMarkCanOmmit(context, ',')
				if !ok {
					context.parsePos = pos
					return ParseCRLF(context)
				}

				if !macthMark {
					context.parsePos = pos
					return ParseCRLF(context)
				}

				header, ok = info.ParseFunc(context)
				if !ok {
					return false
				}
			}
		}
	} else {
		header = NewSipHeader(context)
		if header == ABNF_PTR_NIL {
			return false
		}

		h := header.GetSipHeader(context)
		h.id = headerIndex
		h.hvalue = parseRawHeaderValue(context)
		if h.hvalue == ABNF_PTR_NIL {
			return false
		}
	}

	return headerSetter.SetHeaders(context, headerIndex, header)
}

func parseUnknownHeader(context *Context, hname AbnfPtr, headerSetter SipHeadersSetter) (ok bool) {
	header := NewSipHeader(context)
	if header == ABNF_PTR_NIL {
		return false
	}

	h := header.GetSipHeader(context)
	h.id = SIP_HDR_UNKNOWN
	h.hname = hname
	h.hvalue = parseRawHeaderValue(context)
	if h.hvalue == ABNF_PTR_NIL {
		return false
	}

	ok = headerSetter.SetHeaders(context, SIP_HDR_UNKNOWN, header)
	if !ok {
		return false
	}

	return ok
}

func parseRawHeaderEx(context *Context, headerIndex SipHeaderIndexType, hname AbnfPtr) (header AbnfPtr, ok bool) {
	header = NewSipHeader(context)
	if header == ABNF_PTR_NIL {
		return ABNF_PTR_NIL, false
	}

	h := header.GetSipHeader(context)
	h.id = headerIndex
	h.hname = hname
	h.hvalue = parseRawHeaderValue(context)
	if h.hvalue == ABNF_PTR_NIL {
		return ABNF_PTR_NIL, false
	}

	return header, true
}

func parseRawHeaderValue(context *Context) (hvalue AbnfPtr) {
	pos := context.parsePos
	begin, ok := FindCrlfByRFC3261(context)
	if !ok {
		return ABNF_PTR_NIL
	}

	hvalue = AllocCString(context, context.parseSrc[pos:begin])
	if hvalue == ABNF_PTR_NIL {
		return ABNF_PTR_NIL
	}

	return hvalue
}

func FindCrlfByRFC3261(context *Context) (begin AbnfPos, ok bool) {
	/* state diagram
	 *                                                              other char/found
	 *       |----------|    CR    |-------|    LF    |---------|---------------------->end
	 *  |--->| ST_START | -------> | ST_CR |--------->| ST_CRLF |                        ^
	 *  |    |----------|          |-------|          |---------|                        |
	 *  |                               |                  |        other char/not found |
	 *  |                               |------------------+-----------------------------|
	 *  |            WSP                                   |
	 *  |--------------------------------------------------|
	 *
	 *  it is an error if any character except 'LF' is after 'CR' in this routine.
	 *  'CR' or 'LF' is not equal to 'CRLF' in this routine
	 */
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	end := context.parsePos
	pos := context.parsePos

	//for end < len1 {
	for {
		/*
			for ; (end < len1) && (src[end] != '\n'); end++ {
			}
			if end >= len1 {
				context.parsePos = end
				return end, false
			}
			end++
			//*/

		//*
		p1 := bytes.IndexByte(src[end:], '\n')
		if p1 == -1 {
			context.parsePos = len1
			return len1, false
		}
		end += uint(p1) + 1
		//*/

		if end >= len1 {
			break
		}

		if !IsWspChar(src[end]) {
			break
		}
	}

	if ((pos + 2) < end) && (src[end-2] == '\r') {
		begin = end - 2
	} else {
		begin = end - 1
	}

	context.parsePos = end
	return begin, true
}
