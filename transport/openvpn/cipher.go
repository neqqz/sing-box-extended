package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	AESGCMTagSize = 16
	AESGCMIVSize  = 12
	CBCIVSize     = aes.BlockSize
)

type DataCipher interface {
	Encrypt(header []byte, packetID uint32, payload []byte) ([]byte, error)
	Decrypt(packet []byte, headerSize int) (plaintext []byte, packetID uint32, err error)
}

type AEADDataCipher struct {
	send           cipher.AEAD
	recv           cipher.AEAD
	sendImplicitIV [AESGCMIVSize]byte
	recvImplicitIV [AESGCMIVSize]byte
}

func NewAEADCipher(keys *KeyMaterial, cipherName string) (*AEADDataCipher, error) {
	var send, recv cipher.AEAD
	var err error
	if cipherName == CipherCHACHA20POLY {
		send, err = chacha20poly1305.New(keys.SendCipherKey)
		if err != nil {
			return nil, err
		}
		recv, err = chacha20poly1305.New(keys.RecvCipherKey)
		if err != nil {
			return nil, err
		}
	} else {
		sendBlock, err := aes.NewCipher(keys.SendCipherKey)
		if err != nil {
			return nil, err
		}
		recvBlock, err := aes.NewCipher(keys.RecvCipherKey)
		if err != nil {
			return nil, err
		}
		send, err = cipher.NewGCMWithTagSize(sendBlock, AESGCMTagSize)
		if err != nil {
			return nil, err
		}
		recv, err = cipher.NewGCMWithTagSize(recvBlock, AESGCMTagSize)
		if err != nil {
			return nil, err
		}
	}
	if len(keys.SendHMACKey) < AESGCMIVSize-4 || len(keys.RecvHMACKey) < AESGCMIVSize-4 {
		return nil, errors.New("openvpn implicit IV keys are too short")
	}
	g := &AEADDataCipher{send: send, recv: recv}
	copy(g.sendImplicitIV[4:], keys.SendHMACKey[:AESGCMIVSize-4])
	copy(g.recvImplicitIV[4:], keys.RecvHMACKey[:AESGCMIVSize-4])
	return g, nil
}

func (g *AEADDataCipher) Encrypt(header []byte, packetID uint32, payload []byte) ([]byte, error) {
	var pidBytes [4]byte
	binary.BigEndian.PutUint32(pidBytes[:], packetID)
	nonce := g.nonce(packetID, g.sendImplicitIV)
	ad := append(header, pidBytes[:]...)
	sealed := g.send.Seal(nil, nonce[:], payload, ad)
	out := make([]byte, 0, len(header)+4+len(sealed))
	out = append(out, header...)
	out = append(out, pidBytes[:]...)
	out = append(out, sealed[len(sealed)-AESGCMTagSize:]...)
	out = append(out, sealed[:len(sealed)-AESGCMTagSize]...)
	return out, nil
}

func (g *AEADDataCipher) Decrypt(packet []byte, headerSize int) ([]byte, uint32, error) {
	if len(packet) < headerSize+4+AESGCMTagSize+1 {
		return nil, 0, errors.New("openvpn gcm data packet too short")
	}
	header := packet[:headerSize]
	pidBytes := packet[headerSize : headerSize+4]
	tag := packet[headerSize+4 : headerSize+4+AESGCMTagSize]
	ciphertext := packet[headerSize+4+AESGCMTagSize:]
	combined := append(ciphertext, tag...)
	ad := append(header, pidBytes...)
	packetID := binary.BigEndian.Uint32(pidBytes)
	nonce := g.nonce(packetID, g.recvImplicitIV)
	plain, err := g.recv.Open(nil, nonce[:], combined, ad)
	if err != nil {
		return nil, 0, err
	}
	return plain, packetID, nil
}

func (g *AEADDataCipher) nonce(packetID uint32, implicit [AESGCMIVSize]byte) [AESGCMIVSize]byte {
	nonce := implicit
	binary.BigEndian.PutUint32(nonce[:4], binary.BigEndian.Uint32(nonce[:4])^packetID)
	return nonce
}

type CBCDataCipher struct {
	sendBlock cipher.Block
	recvBlock cipher.Block
	sendHMAC  []byte
	recvHMAC  []byte
	newHash   func() hash.Hash
	hmacSize  int
}

func NewCBCCipher(keys *KeyMaterial, auth string) (*CBCDataCipher, error) {
	sendBlock, err := aes.NewCipher(keys.SendCipherKey)
	if err != nil {
		return nil, err
	}
	recvBlock, err := aes.NewCipher(keys.RecvCipherKey)
	if err != nil {
		return nil, err
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
	return &CBCDataCipher{
		sendBlock: sendBlock,
		recvBlock: recvBlock,
		sendHMAC:  cloneBytes(keys.SendHMACKey[:hmacSize]),
		recvHMAC:  cloneBytes(keys.RecvHMACKey[:hmacSize]),
		newHash:   newHash,
		hmacSize:  hmacSize,
	}, nil
}

func (c *CBCDataCipher) Encrypt(header []byte, packetID uint32, payload []byte) ([]byte, error) {
	var pidBytes [4]byte
	binary.BigEndian.PutUint32(pidBytes[:], packetID)
	plain := append(pidBytes[:], payload...)
	padLen := aes.BlockSize - (len(plain) % aes.BlockSize)
	for i := 0; i < padLen; i++ {
		plain = append(plain, byte(padLen))
	}
	iv := make([]byte, CBCIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(c.sendBlock, iv).CryptBlocks(ct, plain)
	mac := hmac.New(c.newHash, c.sendHMAC)
	mac.Write(iv)
	mac.Write(ct)
	tag := mac.Sum(nil)
	out := make([]byte, 0, len(header)+c.hmacSize+CBCIVSize+len(ct))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

func (c *CBCDataCipher) Decrypt(packet []byte, headerSize int) ([]byte, uint32, error) {
	minSize := headerSize + c.hmacSize + CBCIVSize + aes.BlockSize
	if len(packet) < minSize {
		return nil, 0, errors.New("openvpn cbc data packet too short")
	}
	tag := packet[headerSize : headerSize+c.hmacSize]
	iv := packet[headerSize+c.hmacSize : headerSize+c.hmacSize+CBCIVSize]
	ct := packet[headerSize+c.hmacSize+CBCIVSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, 0, errors.New("openvpn cbc ciphertext not block-aligned")
	}
	mac := hmac.New(c.newHash, c.recvHMAC)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, 0, errors.New("openvpn cbc hmac verification failed")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c.recvBlock, iv).CryptBlocks(plain, ct)
	padLen := int(plain[len(plain)-1])
	if padLen < 1 || padLen > aes.BlockSize {
		return nil, 0, errors.New("openvpn cbc invalid padding")
	}
	plain = plain[:len(plain)-padLen]
	if len(plain) < 4 {
		return nil, 0, errors.New("openvpn cbc payload too short")
	}
	packetID := binary.BigEndian.Uint32(plain[:4])
	return plain[4:], packetID, nil
}

func CipherKeyLength(cipher string) int {
	switch cipher {
	case CipherAES128GCM, CipherAES128CBC:
		return 16
	case CipherAES192GCM, CipherAES192CBC:
		return 24
	default:
		return 32
	}
}

func IsAEAD(cipher string) bool {
	switch cipher {
	case CipherAES128GCM, CipherAES192GCM, CipherAES256GCM, CipherCHACHA20POLY:
		return true
	default:
		return false
	}
}
