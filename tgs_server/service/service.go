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

	cryptoutil "security-project/common/crypto"
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
	h, payload, err := krb.ReadPacket(conn, 64*1024)
	if err != nil {
		code := krb.CodeFromError(err)
		if code != krb.ErrSocketRecv {
			_ = s.writeError(conn, s.nextServerSeq(), code)
		}
		return
	}
	if err := s.replay.Check(h.Timestamp, h.SeqNum); err != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(err))
		return
	}
	if err := krb.CheckHeaderType(h.MsgType, krb.MsgTGSReq); err != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(err))
		return
	}
	respType, respPayload, respErr := s.handleTGSReq(h, payload, peerADc)
	if respErr != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(respErr))
		return
	}
	_ = krb.WritePacket(conn, respType, s.nextServerSeq(), uint32(time.Now().Unix()), respPayload)
}

func (s *Service) handleTGSReq(h krb.ProtocolHeader, payload []byte, peerADc uint32) (uint8, []byte, error) {
	req, err := krb.ParseTGSReqPayload(payload)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	ticket, err := krb.DecodeTicketTGS(req.TicketTGS, s.state.Ktgs)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if ticket.IDTGS.Len > 0 && string(ticket.IDTGS.Data) != s.state.IDTGS {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}
	expire := ticket.TS2 + ticket.Lifetime
	if uint32(time.Now().Unix()) > expire {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}
	auth, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticket.KeyCTGS)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if string(auth.IDClient.Data) != string(ticket.IDClient.Data) {
		err := krb.ErrorFromCode(krb.ErrAuthMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrAuthMismatch), err
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc && auth.ADc != peerADc {
		err := krb.ErrorFromCode(krb.ErrADMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrADMismatch), err
	}
	secret, ok := s.state.Services[string(req.IDV.Data)]
	if !ok {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}
	keyCV, err := rand8()
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrKeyDerive)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrKeyDerive), err
	}
	ts4 := uint32(time.Now().Unix())
	ticketVPlain, err := krb.BuildTicketVPlain(string(ticket.IDClient.Data), ticket.ADc, string(req.IDV.Data), keyCV, ts4, s.Config.TicketLifetimeSec)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(secret.Kv, ticketVPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	innerPlain, err := krb.BuildTGSRepPlain(keyCV, string(req.IDV.Data), ts4, s.Config.TicketLifetimeSec, ticketVCipher)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	encPart, err := cryptoutil.EncryptDESCBC(ticket.KeyCTGS, innerPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	resp, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	return krb.MsgTGSRep, resp, nil
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	return krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
}

func rand8() ([8]byte, error) {
	var out [8]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
