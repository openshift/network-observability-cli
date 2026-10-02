package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestUnverifiedAgentTupleCannotAnnotateAnotherConnection(t *testing.T) {
	for _, tupleSource := range []string{"", "proc", "kernel"} {
		t.Run(tupleSource, func(t *testing.T) {
			var output bytes.Buffer
			buf := newWirePacketBuffer(nil, time.Minute, func(m config.GenericMap) {
				writePlaintextJSONL(&output, &m)
			}, captureFilters{})
			stamp := float64(time.Now().UnixMilli())
			pt := config.GenericMap{
				"TimeFlowStartMs": stamp, "Direction": "read", "TLSSource": "openssl",
				"RecordType": "plaintext", "TupleSource": tupleSource,
				"SrcAddr": "10.244.1.2", "SrcPort": float64(8443),
				"DstAddr": "10.244.1.3", "DstPort": float64(45008),
				"Plaintext": base64.StdEncoding.EncodeToString([]byte("GET /marker HTTP/1.1\r\n\r\n")),
			}
			// A guessed tuple can exactly match a real wire connection while
			// belonging to a different request. Agreement alone isn't proof.
			wire := config.GenericMap{
				"TimeFlowStartMs": stamp, "SrcAddr": "10.244.1.3", "SrcPort": float64(45008),
				"DstAddr": "10.244.1.2", "DstPort": float64(8443),
			}
			frame := buildTestTCPFrameWithTuple(t, net.ParseIP("10.244.1.3"), net.ParseIP("10.244.1.2"), 45008, 8443, bytes.Repeat([]byte("x"), 128))
			assert.NoError(t, buf.Enqueue(wire, base64.StdEncoding.EncodeToString(frame)))
			handlePlaintextRecord(pt, buf, &output)
			buf.Close()
			var exported config.GenericMap
			assert.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &exported))
			assert.Equal(t, tupleSource == "kernel", exported["PcapAnnotated"])
			if tupleSource != "kernel" {
				assert.NotContains(t, exported, "SrcAddr")
				assert.NotContains(t, exported, "DstPort")
			} else {
				assert.Equal(t, "10.244.1.3", exported["SrcAddr"])
			}
		})
	}
}

func TestUnmatchedKernelReadKeepsNetworkDirection(t *testing.T) {
	m := config.GenericMap{
		"TupleSource": "kernel", "Direction": "read",
		"SrcAddr": "10.244.1.2", "SrcPort": float64(8443), "SrcK8S_Name": "server",
		"DstAddr": "10.244.1.3", "DstPort": float64(45008), "DstK8S_Name": "client",
	}
	prepareUnmatchedPlaintext(&m)
	assert.Equal(t, "10.244.1.3", m["SrcAddr"])
	assert.Equal(t, float64(45008), m["SrcPort"])
	assert.Equal(t, "client", m["SrcK8S_Name"])
	assert.Equal(t, "server", m["DstK8S_Name"])
}

func TestPacketCaptureIdleDeadlineFlushesFile(t *testing.T) {
	t.Chdir(t.TempDir())
	oldPort, oldFilename, oldMaxTime, oldStartup, oldEnded := port, filename, maxTime, startupTime, captureEnded
	t.Cleanup(func() {
		port, filename, maxTime, startupTime, captureEnded = oldPort, oldFilename, oldMaxTime, oldStartup, oldEnded
	})
	port, filename, maxTime, startupTime = 0, "idle", 10*time.Millisecond, time.Now()
	startPacketCollector()
	assert.True(t, captureEnded)
	f, err := os.Open("output/pcap/idle.pcapng")
	assert.NoError(t, err)
	defer f.Close()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	assert.NoError(t, err, "even an idle capture must flush its PCAP header")
	_, _, err = r.ReadPacketData()
	assert.ErrorIs(t, err, io.EOF)
}

func TestPacketStopWaitsForCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ngwMu.Lock()
	activePacketStop = func() { cancel(); <-done }
	ngwMu.Unlock()
	t.Cleanup(clearActivePacketWriter)
	stopped := make(chan bool, 1)
	go func() { stopped <- stopActivePacketCapture() }()
	<-ctx.Done()
	select {
	case <-stopped:
		t.Fatal("stop returned before pending output was flushed")
	default:
	}
	close(done)
	assert.True(t, <-stopped)
}
