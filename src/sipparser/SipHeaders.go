package sipparser

import (
	//"fmt"
	_ "unsafe"
)

type KnownSipHeaders interface {
	SetKnownHeades(context *ParseContext, headerIndex SipHeaderIndexType, header AbnfPtr) bool
	EncodeKnownHeaders(context *ParseContext, buf *AbnfByteBuffer)
}

type SipHeader struct {
	info   *SipHeaderInfo
	parsed AbnfPtr
}

func FindCrlfByRFC3261(context *ParseContext) (ok bool) {
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

	//for end < len1 {
	for {
		for ; (end < len1) && (src[end] != '\n'); end++ {
		}
		if end >= len1 {
			/* no CRLF" */
			context.parsePos = end
			return false
		}
		end++

		if end >= len1 {
			break
		}

		if !IsWspChar(src[end]) {
			break
		}
	}

	context.parsePos = end
	return true
}
