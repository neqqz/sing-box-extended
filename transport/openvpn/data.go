package openvpn

import (
	"errors"
	"fmt"
	"sync"
)

const (
	PeerIDUnset uint32 = 0xffffff
)

type DataChannel struct {
	cipher       DataCipher
	keyID        uint8
	peerID       uint32
	compLZO      bool
	mu           sync.Mutex
	sendPacketID uint32
}

func NewDataChannel(cipher DataCipher, peerID uint32, compLZO bool) *DataChannel {
	return &DataChannel{
		cipher:  cipher,
		peerID:  peerID,
		compLZO: compLZO,
	}
}

func (d *DataChannel) Encrypt(packet []byte) ([]byte, error) {
	if d.compLZO {
		p := make([]byte, 1+len(packet))
		p[0] = 0xFA
		copy(p[1:], packet)
		packet = p
	}
	d.mu.Lock()
	d.sendPacketID++
	packetID := d.sendPacketID
	d.mu.Unlock()
	return d.cipher.Encrypt(d.dataHeader(), packetID, packet)
}

func (d *DataChannel) Decrypt(packet []byte) ([]byte, error) {
	if len(packet) < 1 {
		return nil, errors.New("empty openvpn data packet")
	}
	opcode, _ := parseOpcodeKeyID(packet[0])
	headerSize := 1
	if opcode == PDataV2 {
		headerSize = 4
	}
	plain, err := d.cipher.Decrypt(packet, headerSize)
	if err != nil {
		return nil, err
	}
	if d.compLZO {
		if len(plain) < 1 {
			return nil, errors.New("openvpn comp-lzo packet too short")
		}
		if plain[0] != 0xFA {
			return nil, fmt.Errorf("openvpn compressed packet not supported (byte: 0x%02x)", plain[0])
		}
		plain = plain[1:]
	}
	return plain, nil
}

func (d *DataChannel) dataHeader() []byte {
	if d.peerID != PeerIDUnset {
		return []byte{
			opcodeKeyID(PDataV2, d.keyID),
			byte(d.peerID >> 16),
			byte(d.peerID >> 8),
			byte(d.peerID),
		}
	}
	return []byte{opcodeKeyID(PDataV1, d.keyID)}
}

func ParsePeerID(options string) uint32 {
	for _, field := range splitPushOptions(options) {
		if len(field) > len("peer-id ") && field[:len("peer-id ")] == "peer-id " {
			var id uint32
			if _, err := fmt.Sscanf(field, "peer-id %d", &id); err == nil && id <= PeerIDUnset {
				return id
			}
		}
	}
	return PeerIDUnset
}
