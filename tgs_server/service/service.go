package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/tgs_server/config"
)

type Service struct {
	Config     *config.Config
	state      *krb.TGSState
	replay     *krb.ReplayWindow
	startTime  time.Time
	nextSeq    uint32
	httpServer *http.Server
}

func NewService(configPath string) *Service {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("load config: %v", err))
	}
	ktgs, _ := krb.LoadKey8(cfg.KTGSPath, "tgs-ktgs")
	st := &krb.TGSState{
		Ktgs:     ktgs,
		IDTGS:    "TGS",
		Services: make(map[string]krb.ServiceSecret, len(cfg.ServiceDB)),
	}
	for _, s := range cfg.ServiceDB {
		kv, _ := krb.LoadKey8(s.KVPath, "kv:"+s.IDV)
		st.Services[s.IDV] = krb.ServiceSecret{IDV: s.IDV, Kv: kv}
	}
	return &Service{
		Config:    cfg,
		state:     st,
		replay:    krb.NewReplayWindow(1024),
		startTime: time.Now(),
	}
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		go s.runWebUI()
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("[TGS] listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TGS] accept failed: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node_id":               s.Config.NodeID,
			"uptime_s":              int64(time.Since(s.startTime).Seconds()),
			"total_ticket_v_issued": atomic.LoadUint32(&s.nextSeq),
			"total_auth_fail":       0,
		})
	})
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		services := make([]map[string]any, 0, len(s.Config.ServiceDB))
		for _, item := range s.Config.ServiceDB {
			services = append(services, map[string]any{"id_v": item.IDV, "addr": item.Addr})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"services": services})
	})
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("[TGS] webui listening on %s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[TGS] webui failed: %v", err)
	}
}

func (s *Service) nextServerSeq() uint32 {
	return atomic.AddUint32(&s.nextSeq, 1)
}

func (s *Service) handleConnection(conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	peerADc := krb.PeerIP(conn)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	h, payload, code := krb.ReadPacket(conn, 64*1024)
	if code != krb.KRBOK {
		if code != krb.ErrSocketRecv {
			_ = s.writeError(conn, s.nextServerSeq(), code)
		}
		return
	}
	if code := s.replay.Check(h.Timestamp, h.SeqNum); code != krb.KRBOK {
		_ = s.writeError(conn, s.nextServerSeq(), code)
		return
	}
	if code := krb.CheckHeaderType(h.MsgType, krb.MsgTGSReq); code != krb.KRBOK {
		_ = s.writeError(conn, s.nextServerSeq(), code)
		return
	}
	respType, respPayload, respCode := s.handleTGSReq(h, payload, peerADc)
	if respCode != krb.KRBOK {
		_ = s.writeError(conn, s.nextServerSeq(), respCode)
		return
	}
	_ = krb.WritePacket(conn, respType, s.nextServerSeq(), uint32(time.Now().Unix()), respPayload)
}

func (s *Service) handleTGSReq(h krb.KerHeader, payload []byte, peerADc uint32) (uint8, []byte, int32) {
	req, code := krb.ParseTGSReqPayload(payload)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	ticket, code := krb.DecodeTicketTGS(req.TicketTGS, s.state.Ktgs)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	if ticket.IDTGS.Len > 0 && string(ticket.IDTGS.Data) != s.state.IDTGS {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), krb.ErrTicketInvalid
	}
	expire := ticket.TS2 + ticket.Lifetime
	if uint32(time.Now().Unix()) > expire {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), krb.ErrTicketExpired
	}
	auth, code := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticket.KeyCTGS)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	if string(auth.IDClient.Data) != string(ticket.IDClient.Data) {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrAuthMismatch), krb.ErrAuthMismatch
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc && auth.ADc != peerADc {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrADMismatch), krb.ErrADMismatch
	}
	secret, ok := s.state.Services[string(req.IDV.Data)]
	if !ok {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), krb.ErrTicketInvalid
	}
	keyCV, code := rand8()
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	ts4 := uint32(time.Now().Unix())
	ticketVPlain, code := krb.BuildTicketVPlain(string(ticket.IDClient.Data), ticket.ADc, string(req.IDV.Data), keyCV, ts4, s.Config.TicketLifetimeSec)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	ticketVCipher, err := krb.EncryptDESCBC(secret.Kv, ticketVPlain)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), krb.ErrDESPadding
	}
	innerPlain, code := krb.BuildTGSRepPlain(keyCV, string(req.IDV.Data), ts4, s.Config.TicketLifetimeSec, ticketVCipher)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	encPart, err := krb.EncryptDESCBC(ticket.KeyCTGS, innerPlain)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), krb.ErrDESPadding
	}
	resp, code := krb.BuildASRepPayload(encPart)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	return krb.MsgTGSRep, resp, krb.KRBOK
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	return krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
}

func rand8() ([8]byte, int32) {
	var out [8]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, krb.ErrKeyDerive
	}
	return out, krb.KRBOK
}
