package sipparser

func SipMsgRawScan(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))

	for context.parsePos < len1 {
		if IsCRLF(src, AbnfPos(context.parsePos)) {
			/* reach message-body */
			context.parsePos += 2
			return true
		}

		if !FindCrlfByRFC3261(context) {
			return false
		}

		//fmt.Println("pos =", context.parsePos)
	}
	return true
}
