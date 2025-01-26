package capture

import (
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"realtime-network-instruction-detection/pkg/model"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FlowFeatures stores all the network flow metrics
type FlowFeatures struct {
    FlowDuration        float64
    TotalFwdPackets     int
    FwdPacketLengthMin  int64
    FwdPacketLengthMax  int64
    FwdPacketLengthStd  float64
    FwdIATTotal         float64
    FwdIATMean          float64
    FwdIATStd           float64
    FwdIATMax           float64
    FwdHeaderLength     int
    FwdActDataPackets   int
    FINFlagCount        int
    PacketLengthStd     float64
    AvgPacketSize       float64
}

// PacketInfo stores information about individual packets
type PacketInfo struct {
    Timestamp  time.Time
    Length     int64
    HeaderLen  int
    HasFINFlag bool
}

// calculateStdDev calculates standard deviation
func calculateStdDev(values []float64, mean float64) float64 {
    if len(values) == 0 {
        return 0
    }
    var sumSquares float64
    for _, v := range values {
        diff := v - mean
        sumSquares += diff * diff
    }
    return math.Sqrt(sumSquares / float64(len(values)))
}

// resetFeatures resets flow features for a new flow
func resetFeatures(features *FlowFeatures) {
    *features = FlowFeatures{
        FwdPacketLengthMin: math.MaxInt64,
    }
}

// captureWebServerTraffic captures traffic and computes features
func CaptureWebServerTraffic(interfaceName string) {
    // Open device
    handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // BPF filter modified for port 8000
    filter := "tcp and host localhost and port 8000"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }

    var (
        features           FlowFeatures
        firstPacketTime    time.Time
        lastPacketTime     time.Time
        fwdPacketLengths   []float64
        fwdIATs            []float64
        lastFwdPacketTime  time.Time
        totalLength        float64
    )

    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packets := packetSource.Packets()

    fmt.Println("\nStarting web server traffic capture... Press Ctrl+C to stop")

    ticker := time.NewTicker(2 * time.Second) // Print features every 2 seconds
    go func() {
        for range ticker.C {
            if features.TotalFwdPackets > 0 {
                calculateFlowMetrics(&features, firstPacketTime, lastPacketTime, fwdPacketLengths, fwdIATs, totalLength)
                // printFlowFeatures(&features)
				FlowFeaturesPredication(&features)

				resetFeatures(&features)
				resetFeatures(&features)
            	firstPacketTime = time.Time{}
            	lastPacketTime = time.Time{}
            	fwdPacketLengths = nil
            	fwdIATs = nil
            	totalLength = 0
            }
        }
    }()

    for {
        select {
        case <-signalChan:
            ticker.Stop()
            fmt.Println("\nCapture stopped.")
            return

        case packet := <-packets:
            if packet == nil {
                continue
            }

            ipLayer := packet.Layer(layers.LayerTypeIPv4)
            tcpLayer := packet.Layer(layers.LayerTypeTCP)
            if ipLayer == nil || tcpLayer == nil {
                continue
            }

            tcp, _ := tcpLayer.(*layers.TCP)
            pktInfo := PacketInfo{
                Timestamp:  packet.Metadata().Timestamp,
                Length:     int64(len(packet.Data())),
                HeaderLen:  len(packet.Layer(layers.LayerTypeIPv4).LayerContents()),
                HasFINFlag: tcp.FIN,
            }

            if firstPacketTime.IsZero() {
                firstPacketTime = pktInfo.Timestamp
            }
            lastPacketTime = pktInfo.Timestamp

            features.TotalFwdPackets++
            features.FwdHeaderLength += pktInfo.HeaderLen
            if pktInfo.Length < features.FwdPacketLengthMin {
                features.FwdPacketLengthMin = pktInfo.Length
            }
            if pktInfo.Length > features.FwdPacketLengthMax {
                features.FwdPacketLengthMax = pktInfo.Length
            }

            fwdPacketLengths = append(fwdPacketLengths, float64(pktInfo.Length))
            totalLength += float64(pktInfo.Length)

            if !lastFwdPacketTime.IsZero() {
                iat := pktInfo.Timestamp.Sub(lastFwdPacketTime).Seconds()
                fwdIATs = append(fwdIATs, iat)
                features.FwdIATTotal += iat
                if iat > features.FwdIATMax {
                    features.FwdIATMax = iat
                }
            }
            lastFwdPacketTime = pktInfo.Timestamp

            if pktInfo.HasFINFlag {
                features.FINFlagCount++
            }
        }
    }
}

// calculateFlowMetrics calculates flow metrics
func calculateFlowMetrics(features *FlowFeatures, firstPacketTime, lastPacketTime time.Time, fwdPacketLengths, fwdIATs []float64, totalLength float64) {
    features.FlowDuration = lastPacketTime.Sub(firstPacketTime).Seconds()
    if features.TotalFwdPackets > 0 {
        features.FwdIATMean = features.FwdIATTotal / float64(features.TotalFwdPackets-1)
        features.FwdPacketLengthStd = calculateStdDev(fwdPacketLengths, totalLength/float64(features.TotalFwdPackets))
        features.FwdIATStd = calculateStdDev(fwdIATs, features.FwdIATMean)
        features.AvgPacketSize = totalLength / float64(features.TotalFwdPackets)
        features.PacketLengthStd = calculateStdDev(fwdPacketLengths, features.AvgPacketSize)
    }
}

// printFlowFeatures prints the flow features to the console
func printFlowFeatures(features *FlowFeatures) {
    fmt.Printf("\nReal-time Flow Features:\n")
    fmt.Printf("Flow Duration: %.2f seconds\n", features.FlowDuration)
    fmt.Printf("Total Forward Packets: %d\n", features.TotalFwdPackets)
    fmt.Printf("Min Forward Packet Length: %d\n", features.FwdPacketLengthMin)
    fmt.Printf("Max Forward Packet Length: %d\n", features.FwdPacketLengthMax)
    fmt.Printf("StdDev Forward Packet Length: %.2f\n", features.FwdPacketLengthStd)
    fmt.Printf("Forward IAT Total: %.2f\n", features.FwdIATTotal)
    fmt.Printf("Forward IAT Mean: %.2f\n", features.FwdIATMean)
    fmt.Printf("Forward IAT StdDev: %.2f\n", features.FwdIATStd)
    fmt.Printf("Forward IAT Max: %.2f\n", features.FwdIATMax)
    fmt.Printf("Forward Header Length: %d\n", features.FwdHeaderLength)
    fmt.Printf("Forward ACT Data Packets: %d\n", features.FwdActDataPackets)
    fmt.Printf("FIN Flag Count: %d\n", features.FINFlagCount)
    fmt.Printf("Packet Length StdDev: %.2f\n", features.PacketLengthStd)
    fmt.Printf("Avg Packet Size: %.2f\n", features.AvgPacketSize)
}

func ToFloat32Slice(f *FlowFeatures) []float32 {
	return []float32{
		float32(f.FlowDuration),
		float32(f.TotalFwdPackets),
		float32(f.FwdPacketLengthMin),
		float32(f.FwdPacketLengthMax),
		float32(f.FwdPacketLengthStd),
		float32(f.FwdIATTotal),
		float32(f.FwdIATMean),
		float32(f.FwdIATStd),
		float32(f.FwdIATMax),
		float32(f.FwdHeaderLength),
		float32(f.FwdActDataPackets),
		float32(f.FINFlagCount),
		float32(f.PacketLengthStd),
		float32(f.AvgPacketSize),
	}
}

func FlowFeaturesPredication(features *FlowFeatures) {
    inputs := ToFloat32Slice(features)
	model.Predict(inputs)
}