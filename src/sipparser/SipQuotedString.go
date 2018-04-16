package sipparser

import (
	_ "unsafe"
)

func EncodeSipQuotedString(context *ParseContext, buf *AbnfByteBuffer, quotedString AbnfPtr) {
	buf.WriteByte('"')
	quotedString.WriteCString(context, buf)
	buf.WriteByte('"')
}
