package sipparser

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/lioneagle/goutil/src/chars"
)

const (
	SIP_COMMON_HDR_START_LINE          = 0
	SIP_COMMON_HDR_VIA                 = 1
	SIP_COMMON_HDR_ROUTE               = 2
	SIP_COMMON_HDR_CONTACT             = 3
	SIP_COMMON_HDR_FROM                = 4
	SIP_COMMON_HDR_TO                  = 5
	SIP_COMMON_HDR_CALL_ID             = 6
	SIP_COMMON_HDR_CONTENT_LENGTH      = 7
	SIP_COMMON_HDR_CSEQ                = 8
	SIP_COMMON_HDR_RECORD_ROUTE        = 9
	SIP_COMMON_HDR_CONTENT_TYPE        = 10
	SIP_COMMON_HDR_MAX_FORWARDS        = 11
	SIP_COMMON_HDR_SUPPORTED           = 12
	SIP_COMMON_HDR_ALLOW               = 13
	SIP_COMMON_HDR_EVENT               = 14
	SIP_COMMON_HDR_CONTENT_DISPOSITION = 15
	SIP_COMMON_HDR_SESSION_EXPIRES     = 16
	SIP_COMMON_HDR_MIME_VERSION        = 17
	SIP_COMMON_HDR_REFER_TO            = 18
	SIP_COMMON_HDR_REFERRED_BY         = 19
	SIP_COMMON_HDR_MAX_NUM             = iota
)

var HeaderIndexToCommonIndex = [SIP_HDR_MAX_NUM]int{
	SIP_HDR_VIA:                 1,
	SIP_HDR_ROUTE:               2,
	SIP_HDR_CONTACT:             3,
	SIP_HDR_FROM:                4,
	SIP_HDR_TO:                  5,
	SIP_HDR_CALL_ID:             6,
	SIP_HDR_CONTENT_LENGTH:      7,
	SIP_HDR_CSEQ:                8,
	SIP_HDR_RECORD_ROUTE:        9,
	SIP_HDR_CONTENT_TYPE:        10,
	SIP_HDR_MAX_FORWARDS:        11,
	SIP_HDR_SUPPORTED:           12,
	SIP_HDR_ALLOW:               13,
	SIP_HDR_EVENT:               14,
	SIP_HDR_CONTENT_DISPOSITION: 15,
}

var CommonIndexToHeaderIndex = [SIP_COMMON_HDR_MAX_NUM]SipHeaderIndexType{
	SIP_COMMON_HDR_VIA:                 SIP_HDR_VIA,
	SIP_COMMON_HDR_ROUTE:               SIP_HDR_ROUTE,
	SIP_COMMON_HDR_CONTACT:             SIP_HDR_CONTACT,
	SIP_COMMON_HDR_FROM:                SIP_HDR_FROM,
	SIP_COMMON_HDR_TO:                  SIP_HDR_TO,
	SIP_COMMON_HDR_CALL_ID:             SIP_HDR_CALL_ID,
	SIP_COMMON_HDR_CONTENT_LENGTH:      SIP_HDR_CONTENT_LENGTH,
	SIP_COMMON_HDR_CSEQ:                SIP_HDR_CSEQ,
	SIP_COMMON_HDR_RECORD_ROUTE:        SIP_HDR_RECORD_ROUTE,
	SIP_COMMON_HDR_CONTENT_TYPE:        SIP_HDR_CONTENT_TYPE,
	SIP_COMMON_HDR_MAX_FORWARDS:        SIP_HDR_MAX_FORWARDS,
	SIP_COMMON_HDR_SUPPORTED:           SIP_HDR_SUPPORTED,
	SIP_COMMON_HDR_ALLOW:               SIP_HDR_ALLOW,
	SIP_COMMON_HDR_EVENT:               SIP_HDR_EVENT,
	SIP_COMMON_HDR_CONTENT_DISPOSITION: SIP_HDR_CONTENT_DISPOSITION,
}

const (
	SIP_COMMON_BODY_SESSION       = 0
	SIP_COMMON_BODY_EARLY_SESSION = 1
	SIP_COMMON_BODY_REG_INFO      = 2
	SIP_COMMON_BODY_MAX_NUM       = iota
)

type SipMsg struct {
	startLine     SipStartLine
	commonHeaders [SIP_COMMON_HDR_MAX_NUM]AbnfPtr
	commonBodies  [SIP_COMMON_BODY_MAX_NUM]AbnfPtr
	headers       AbnfPtr // uncommon headers
	bodies        AbnfPtr // uncommon bodies
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

func ByteSliceIndexNoCase(src []byte, pos AbnfPos, find []byte) (newPos AbnfPos, ok bool) {
	len1 := AbnfPos(len(src))
	len2 := AbnfPos(len(find))

	if len2 <= 0 {
		return 0, false
	}

	newPos = pos
	findPos := 0

	c := chars.ToLower(find[findPos])
	findPos++
	len2--

	for {
		for {
			if newPos >= len1 {
				return 0, false
			}
			sc := chars.ToLower(src[newPos])
			newPos++
			if sc == c {
				break
			}
		}
		if (newPos + len2) >= len1 {
			return 0, false
		}

		if chars.EqualNoCase(src[newPos:newPos+len2], find[findPos:]) {
			break
		}
	}

	return newPos - 1, true
}

func FindSipHeader1(context *ParseContext, name []byte, buf *AbnfByteBuffer) (ok bool) {
	src := context.parseSrc
	newPos := context.parsePos
	firstTime := true
	len1 := AbnfPos(len(src))
	len2 := AbnfPos(len(name))
	num := 0
	short_form := false
	header_with_newline := chars.StringToByteSlice(fmt.Sprintf("\n%s", chars.ByteSliceToString(name)))

	for {
		newPos = context.parsePos
		for {
			newPos, ok = ByteSliceIndexNoCase(src, newPos, header_with_newline)
			if !ok {
				break
			}

			if !firstTime {
				newPos += len2 + 1
				for ; newPos < len1 && IsWspChar(src[newPos]); newPos++ {
				}
			} else {
				newPos++
			}
			begin := newPos

			firstTime = false
			for {
				pos := bytes.IndexByte(src[newPos:], '\n')
				if pos == -1 {
					break
				}

				newPos += AbnfPos(pos)
				if newPos+1 >= len1 {
					break
				}
				if !IsWspChar(src[newPos]) {
					break
				}
			}

			if num > 0 {
				buf.WriteString(", ")
			}
			num++
			buf.Write(src[begin : newPos-1])

			newPos++
		}

		if num > 0 {
			break
		}

		if short_form {
			return num > 0
		}

		short_form = true

		if chars.EqualNoCase(name, chars.StringToByteSlice("Call-ID:")) {
			name = chars.StringToByteSlice("i:")
			header_with_newline = chars.StringToByteSlice("\ni:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Contact:")) {
			name = chars.StringToByteSlice("m:")
			header_with_newline = chars.StringToByteSlice("\nm:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Content-Encoding:")) {
			name = chars.StringToByteSlice("e:")
			header_with_newline = chars.StringToByteSlice("\ne:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Content-Length:")) {
			name = chars.StringToByteSlice("l:")
			header_with_newline = chars.StringToByteSlice("\nl:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Content-Type:")) {
			name = chars.StringToByteSlice("c:")
			header_with_newline = chars.StringToByteSlice("\nc:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("From:")) {
			name = chars.StringToByteSlice("f:")
			header_with_newline = chars.StringToByteSlice("\nf:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("To:")) {
			name = chars.StringToByteSlice("t:")
			header_with_newline = chars.StringToByteSlice("\nt:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Via:")) {
			name = chars.StringToByteSlice("v:")
			header_with_newline = chars.StringToByteSlice("\nv:")
		} else {
			return num > 0
		}
	}

	return num > 0
}

func FindSipHeader2(context *ParseContext, name []byte, shortname []byte) (newPos AbnfPos, ok bool) {
	src := context.parseSrc
	newPos = context.parsePos
	len1 := AbnfPos(len(src))
	len2 := AbnfPos(len(name))
	len3 := AbnfPos(len(shortname))

	for newPos < len1 {
		find := false
		if chars.EqualNoCase(name, src[newPos:newPos+len2]) {
			find = true
			newPos += len2
		} else if chars.EqualNoCase(shortname, src[newPos:newPos+len3]) {
			find = true
			newPos += len3
		}

		if find {
			for ; newPos < len1; newPos++ {
				if !IsWspChar(src[newPos]) {
					break
				}
			}
			if newPos >= len1 {
				return newPos, false
			}

			if src[newPos] == ':' {
				newPos, ok = ParseLWS_2(src, newPos)
				if !ok {
					return newPos, false
				}
				return newPos, true
			}
		}

		p1 := bytes.IndexByte(src[newPos:], '\n')
		if p1 == -1 {
			return newPos, false
		}

		newPos += AbnfPos(p1) + 1
	}

	return newPos, false
}
