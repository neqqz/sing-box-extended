package openvpn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

type TLSAuth struct {
	sendHMACKey []byte
	recvHMACKey []byte
	newHash     func() hash.Hash
	hmacSize    int
}

func NewTLSAuth(staticKey []byte, keyDirection int, auth string) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	key0 := staticKey[:keySlotSize]
	key1 := staticKey[keySlotSize:]
	var sendSlot, recvSlot []byte
	if keyDirection == 1 {
		sendSlot = key1
		recvSlot = key0
	} else {
		sendSlot = key0
		recvSlot = key1
	}
	var newHash func() hash.Hash
	var hmacSize int
	switch auth {
	case AuthMD5:
		newHash = md5.New
		hmacSize = md5.Size
	case AuthSHA256:
		newHash = sha256.New
		hmacSize = sha256.Size
	case AuthSHA384:
		newHash = sha512.New384
		hmacSize = 48
	case AuthSHA512:
		newHash = sha512.New
		hmacSize = sha512.Size
	default:
		newHash = sha1.New
		hmacSize = sha1.Size
	}
	return &TLSAuth{
		sendHMACKey: cloneBytes(sendSlot[64 : 64+hmacSize]),
		recvHMACKey: cloneBytes(recvSlot[64 : 64+hmacSize]),
		newHash:     newHash,
		hmacSize:    hmacSize,
	}, nil
}

func (a *TLSAuth) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-auth header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}
	var pid [TLSCryptPIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)
	mac := hmac.New(a.newHash, a.sendHMACKey)
	mac.Write(pid[:])
	mac.Write(header)
	mac.Write(plaintext)
	tag := mac.Sum(nil)
	out := make([]byte, 0, len(header)+a.hmacSize+TLSCryptPIDSize+len(plaintext))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, pid[:]...)
	out = append(out, plaintext...)
	return out, nil
}

func (a *TLSAuth) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	minLen := TLSCryptHeaderSize + a.hmacSize + TLSCryptPIDSize
	if len(packet) < minLen {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}
	header = cloneBytes(packet[:TLSCryptHeaderSize])
	tag := packet[TLSCryptHeaderSize : TLSCryptHeaderSize+a.hmacSize]
	pidStart := TLSCryptHeaderSize + a.hmacSize
	pid := packet[pidStart : pidStart+TLSCryptPIDSize]
	plaintext = cloneBytes(packet[pidStart+TLSCryptPIDSize:])
	mac := hmac.New(a.newHash, a.recvHMACKey)
	mac.Write(pid)
	mac.Write(header)
	mac.Write(plaintext)
	tagCheck := mac.Sum(nil)
	if !hmac.Equal(tag, tagCheck) {
		return nil, 0, 0, nil, errors.New("tls-auth authentication failed")
	}
	packetID = binary.BigEndian.Uint32(pid[:4])
	unixTime = binary.BigEndian.Uint32(pid[4:])
	return header, packetID, unixTime, plaintext, nil
}
