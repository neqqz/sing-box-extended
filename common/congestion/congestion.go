package congestion

import (
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/sing-quic/congestion_bbr1"
	"github.com/sagernet/sing-quic/congestion_bbr2"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewCongestionControl(name string, cwnd int, timeFunc func() time.Time) (func(conn *quic.Conn) congestion.CongestionControl, error) {
	if timeFunc == nil {
		timeFunc = time.Now
	}
	if cwnd == 0 {
		cwnd = 32
	}
	switch name {
	case "", "bbr":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta2.NewBbrSender(
				congestion_meta2.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(conn.Config().InitialPacketSize),
				congestion.ByteCount(cwnd)*congestion.ByteCount(conn.Config().InitialPacketSize),
			)
		}, nil
	case "bbr_standard":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_bbr1.NewBbrSender(
				congestion_bbr1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(conn.Config().InitialPacketSize),
				congestion_bbr1.InitialCongestionWindowPackets,
				congestion_bbr1.MaxCongestionWindowPackets,
			)
		}, nil
	case "bbr2":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_bbr2.NewBBR2Sender(
				congestion_bbr2.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(conn.Config().InitialPacketSize),
				0,
				false,
			)
		}, nil
	case "bbr2_variant":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_bbr2.NewBBR2Sender(
				congestion_bbr2.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(conn.Config().InitialPacketSize),
				32*congestion.ByteCount(conn.Config().InitialPacketSize),
				true,
			)
		}, nil
	case "cubic":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(conn.Config().InitialPacketSize),
				false,
			)
		}, nil
	case "reno":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(conn.Config().InitialPacketSize),
				true,
			)
		}, nil
	default:
		return nil, E.New("unknown congestion control: ", name)
	}
}
