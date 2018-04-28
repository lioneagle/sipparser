package sipparser

import (
	"fmt"
	"unsafe"
)

func init() {
	/*for i, v := range g_SipHeaderInfos {
		v.index = SipHeaderIndexType(i)
	}*/

	printSize()

}

func printSize() {
	fmt.Println("sizeof(bool)                             =", unsafe.Sizeof(true))
	fmt.Println("sizeof(int)                              =", unsafe.Sizeof(1))
	fmt.Println("sizeof(AbnfPtr)                          =", unsafe.Sizeof(AbnfPtr(1)))
	fmt.Println("sizeof(AbnfRef)                          =", unsafe.Sizeof(AbnfRef{}))
	fmt.Println("sizeof(SipHostPort)                      =", unsafe.Sizeof(SipHostPort{}))
	fmt.Println("sizeof(SipUri)                           =", unsafe.Sizeof(SipUri{}))
	fmt.Println("sizeof(SipUriKnownParams)                =", unsafe.Sizeof(SipUriKnownParams{}))
	fmt.Println("sizeof(SipAddr)                          =", unsafe.Sizeof(SipAddr{}))
	fmt.Println("sizeof(SipGenericParam)                  =", unsafe.Sizeof(SipGenericParam{}))
	fmt.Println("sizeof(SipHeaderFrom)                    =", unsafe.Sizeof(SipHeaderFrom{}))
	fmt.Println("sizeof(SipFromKnownParams)               =", unsafe.Sizeof(SipFromKnownParams{}))
	fmt.Println("sizeof(SipMethod)                        =", unsafe.Sizeof(SipMethod{}))
	fmt.Println("sizeof(SipHeaderCallId)                  =", unsafe.Sizeof(SipHeaderCallId{}))
	fmt.Println("sizeof(SipHeaderCseq)                    =", unsafe.Sizeof(SipHeaderCseq{}))
	fmt.Println("sizeof(SipHeaderMaxForwards)             =", unsafe.Sizeof(SipHeaderMaxForwards{}))
	fmt.Println("sizeof(SipVersion)                       =", unsafe.Sizeof(SipVersion{}))
	fmt.Println("sizeof(SipStartLine)                     =", unsafe.Sizeof(SipStartLine{}))
	fmt.Println("sizeof(SipHeaderRoute)                   =", unsafe.Sizeof(SipHeaderRoute{}))
	fmt.Println("sizeof(SipContactKnownParams)            =", unsafe.Sizeof(SipContactKnownParams{}))
	fmt.Println("sizeof(SipHeaderContact)                 =", unsafe.Sizeof(SipHeaderContact{}))
	fmt.Println("sizeof(SipHeaderContentLength)           =", unsafe.Sizeof(SipHeaderContentLength{}))
	fmt.Println("sizeof(SipViaKnownParams)                =", unsafe.Sizeof(SipViaKnownParams{}))
	fmt.Println("sizeof(SipHeaderVia)                     =", unsafe.Sizeof(SipHeaderVia{}))
	fmt.Println("sizeof(SipContentTypeKnownParams)        =", unsafe.Sizeof(SipContentTypeKnownParams{}))
	fmt.Println("sizeof(SipHeaderContentType)             =", unsafe.Sizeof(SipHeaderContentType{}))
	fmt.Println("sizeof(SipContentDispositionKnownParams) =", unsafe.Sizeof(SipContentDispositionKnownParams{}))
	fmt.Println("sizeof(SipHeaderContentDisposition)      =", unsafe.Sizeof(SipHeaderContentDisposition{}))
	fmt.Println("sizeof(SipHeaderContentLength)           =", unsafe.Sizeof(SipHeaderContentLength{}))
	fmt.Println("sizeof(SipMsg)                           =", unsafe.Sizeof(SipMsg{}))

	fmt.Printf("ABNF_PTR_BIT                             = 0x%X\n", uint(ABNF_PTR_BIT))
	fmt.Printf("ABNF_PTR_MASK                            = 0x%X\n", uint(ABNF_PTR_MASK))
	fmt.Println("SIP_URI_KNOWN_PARAM_MAX_NUM              =", SIP_URI_KNOWN_PARAM_MAX_NUM)
}
