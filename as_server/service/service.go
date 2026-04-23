package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"security-project/as_server/config"
	"security-project/common/krb"
)

type Service struct {
	Config     *config.Config
	state      *krb.ASState
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
	ktgs, _ := krb.LoadKey8(cfg.KtgsPath, "as-ktgs")
	st := &krb.ASState{
		Clients: make(map[string]krb.ASClientSecret, len(cfg.ClientDB)),
		Ktgs:    ktgs,
		IDTGS:   "TGS",
	}
	for _, c := range cfg.ClientDB {
		kc, _ := krb.LoadKey8(c.KcPath, "kc:"+c.ID)
		st.Clients[c.ID] = krb.ASClientSecret{
			IDClient: c.ID,
			Kc:       kc,
			ADc:      c.ADc,
		}
	}
	return &Service{
		Config:    cfg,
		state:     st,
		replay:    krb.NewReplayWindow(cfg.AntiReplayWindow),
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
	log.Printf("[AS] listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[AS] accept failed: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"node_id":          s.Config.NodeID,
			"uptime_s":         int64(time.Since(s.startTime).Seconds()),
			"total_tgt_issued": atomic.LoadUint32(&s.nextSeq),
			"total_auth_fail":  0,
			"thread_pool_size": s.Config.ThreadPoolSize,
			"thread_pool_busy": 0,
			"client_count":     len(s.state.Clients),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			ID      string `json:"id"`
			CertID  string `json:"cert_id"`
			CertExp string `json:"cert_expire"`
		}
		out := make([]item, 0, len(s.Config.ClientDB))
		for _, c := range s.Config.ClientDB {
			out = append(out, item{ID: c.ID, CertID: c.CertPath, CertExp: ""})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"clients": out})
	})
	mux.HandleFunc("/api/keys_summary", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			ClientID  string `json:"client_id"`
			KCTGSHash string `json:"k_ctgs_sha256"`
			IssuedAt  uint32 `json:"issued_at"`
			ExpireAt  uint32 `json:"expire_at"`
		}
		out := make([]item, 0, len(s.state.Clients))
		for id, secret := range s.state.Clients {
			sum := krb.Hash256(secret.Kc[:])
			out = append(out, item{
				ClientID:  id,
				KCTGSHash: hex.EncodeToString(sum[:8]),
				IssuedAt:  uint32(time.Now().Unix()),
				ExpireAt:  uint32(time.Now().Add(time.Duration(s.Config.TicketLifetimeSec) * time.Second).Unix()),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
	})
	mux.HandleFunc("/api/cert/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/cert/")
		for _, c := range s.Config.ClientDB {
			if c.ID != id {
				continue
			}
			if c.CertPath == "" {
				http.NotFound(w, r)
				return
			}
			cert, err := krb.CertLoad(c.CertPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(cert)
			return
		}
		http.NotFound(w, r)
	})
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("[AS] webui listening on %s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[AS] webui failed: %v", err)
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
	for {
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
		if code := krb.CheckHeaderType(h.MsgType, krb.MsgASReq); code != krb.KRBOK {
			_ = s.writeError(conn, s.nextServerSeq(), code)
			return
		}
		respType, respPayload, respCode := s.handleASReq(h, payload, peerADc)
		if respCode != krb.KRBOK {
			_ = s.writeError(conn, s.nextServerSeq(), respCode)
			return
		}
		if err := krb.WritePacket(conn, respType, s.nextServerSeq(), uint32(time.Now().Unix()), respPayload); err != nil {
			return
		}
		return
	}
}

func (s *Service) handleASReq(h krb.KerHeader, payload []byte, peerADc uint32) (uint8, []byte, int32) {
	req, code := krb.ParseASReqPayload(payload)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	secret, ok := s.state.Clients[string(req.IDClient.Data)]
	if !ok {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrClientNotFound), krb.ErrClientNotFound
	}
	secret.ADc = peerADc
	keyCTGS, code := rand8()
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	ts2 := uint32(time.Now().Unix())
	idTGS := string(req.IDTGS.Data)
	if idTGS == "" {
		idTGS = s.state.IDTGS
	}
	ticketPlain, code := krb.BuildTicketTGSPlain(secret, idTGS, keyCTGS, ts2, s.Config.TicketLifetimeSec)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	ticketCipher, err := krb.EncryptDESCBC(s.state.Ktgs, ticketPlain)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), krb.ErrDESPadding
	}
	innerPlain, code := krb.BuildASRepPlain(keyCTGS, idTGS, ts2, s.Config.TicketLifetimeSec, ticketCipher)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	encPart, err := krb.EncryptDESCBC(secret.Kc, innerPlain)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), krb.ErrDESPadding
	}
	resp, code := krb.BuildASRepPayload(encPart)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	return krb.MsgASRep, resp, krb.KRBOK
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
