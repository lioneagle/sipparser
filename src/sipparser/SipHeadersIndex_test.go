package sipparser

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestGetSipHeaderInfoClone(t *testing.T) {
	header1 := &SipHeaderInfo{}
	header2 := header1.Clone()
	test.EXPECT_EQ(t, header1, header2, "")

	header1.Index = 10
	header1.Name = []byte("from")
	header1.ShortName = []byte("f")
	header1.ParseFunc = ParseSipFrom
	header1.EncodeFunc = EncodeSipFromValue
	header1.AppendFunc = AppendSipContactValue
	header1.GetNextFunc = GetNextContactValue
	header1.HasShortName = true
	header1.IsKeyheader = true
	header1.AllowMulti = true
	header1.NeedParse = true
	header2 = header1.Clone()
	test.EXPECT_EQ(t, header1, header2, "")
}

func TestGetSipHeaderInfosClone(t *testing.T) {
	infos := g_SipHeaderInfos.Clone()
	//infos[0].Name = []byte("abc")
	//infos[SIP_HDR_FROM].ParseFunc = nil

	test.EXPECT_EQ(t, infos, g_SipHeaderInfos, "")
}

func TestGetSipHeaderIndex(t *testing.T) {
	for i, v := range g_SipHeaderInfos {
		if v == nil {
			continue
		}

		v := v
		j := i
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			index, _ := GetSipHeaderIndex(v.Name, 0)
			test.EXPECT_EQ(t, index, SipHeaderIndexType(j), "header name = %s", v.Name)

			index, _ = GetSipHeaderIndex(bytes.ToLower(v.Name), 0)
			test.EXPECT_EQ(t, index, SipHeaderIndexType(j), "header name = %s", bytes.ToLower(v.Name))

			index, _ = GetSipHeaderIndex(bytes.ToUpper(v.Name), 0)
			test.EXPECT_EQ(t, index, SipHeaderIndexType(j), "header name = %s", bytes.ToUpper(v.Name))
		})
	}
}

func BenchmarkGetSipHeaderIndex(b *testing.B) {
	b.StopTimer()
	b.SetBytes(2)
	b.ReportAllocs()

	var testdata []*SipHeaderInfo

	for _, v := range g_SipHeaderInfos {
		if v != nil {
			testdata = append(testdata, v)
		}
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		//for _, v := range g_SipHeaderInfos {
		for _, v := range testdata {
			GetSipHeaderIndex(v.Name, 0)
		}
	}
}
