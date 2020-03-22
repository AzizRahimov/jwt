package pkg
import (
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	encode, err := Encode("Parviz",[]byte("par"))
	if err != nil {
		t.Errorf("can't encoding: %v",err)
	}
	if encode != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.IlBhcnZpeiI.CpeBsIFHRbcPt2kQPcZ1tyK7pcI1x56yZ_PCx-20E8s"{
		t.Errorf("incorrectly encoded: %v",encode)
	}
}

func TestDecode(t *testing.T) {
	par:= struct {
		EXP int64 `json:"exp"`
	}{
		EXP: time.Now().Add(time.Hour).Unix(),
	}
	err:= Decode("Parviz", &par)
	if err == nil {
		t.Errorf("can't decoding: %v",err)
	}
	err = Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODQwNDI0NzB9.In1vJz3MOArHS41Z9Wzd7BWMTrTjQsFZkYB7OtV6lPw", &par)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}

}

func TestVerify(t *testing.T) {
	verify, err := Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.IlBhcnZpeiI.CpeBsIFHRbcPt2kQPcZ1tyK7pcI1x56yZ_PCx-20E8s", []byte("par"))
	if err != nil {
		t.Errorf("...%v",err)
	}
	if !verify {
		t.Errorf("Error")
	}
	verify, err = Verify("....", []byte("par"))
	if err == nil{
		t.Errorf("Bad token")
	}

	verify, err = Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.IlBhcnZpeiI.CpeBsIFHRbcPt2kQPcZ1tyK7pcI1x56yZ_PCx-20E8s", []byte("paar"))
	if verify {
		t.Errorf("Not correct token")
	}

}

func TestIsNotExpired(t *testing.T) {
	isNotExpired, err := IsNotExpired("Alif", time.Now())
	if err == nil {
		t.Errorf("%v",err)
	}
	if isNotExpired {
		t.Errorf("...")
	}

}