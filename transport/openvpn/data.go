package openvpn

import (
	"errors"
	"fmt"
	"sync"
)

const (
	PeerIDUnset uint32 = 0xffffff

	dataChannelReplayWindow = 64
)

type DataChannel struct {
	cipher  DataCipher
	keyID   uint8
	peerID  uint32
	compLZO bool

	mu           sync.Mutex
	sendPacketID uint32
	recvHighest  uint32
	recvWindow   uint64
	recvSeen     bool
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
		compressed, err := lzo1xCompressSafe(packet)
		if err != nil {
			return nil, err
		}
		packet = compressed
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
	plain, packetID, err := d.cipher.Decrypt(packet, headerSize)
	if err != nil {
		return nil, err
	}
	if err := d.acceptPacketID(packetID); err != nil {
		return nil, err
	}
	if d.compLZO {
		return lzo1xDecompressSafe(plain)
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

func (d *DataChannel) acceptPacketID(packetID uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.recvSeen {
		d.recvHighest = packetID
		d.recvWindow = 1
		d.recvSeen = true
		return nil
	}

	if packetID > d.recvHighest {
		shift := packetID - d.recvHighest
		if shift >= dataChannelReplayWindow {
			d.recvWindow = 1
		} else {
			d.recvWindow = d.recvWindow<<shift | 1
		}
		d.recvHighest = packetID
		return nil
	}

	diff := d.recvHighest - packetID
	if diff >= dataChannelReplayWindow {
		return fmt.Errorf("openvpn replayed data packet id %d", packetID)
	}
	mask := uint64(1) << diff
	if d.recvWindow&mask != 0 {
		return fmt.Errorf("openvpn replayed data packet id %d", packetID)
	}
	d.recvWindow |= mask
	return nil
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
