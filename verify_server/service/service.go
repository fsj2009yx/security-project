package service

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/verify_server/config"
)

const (
	ptyEventOpenOK = 0x11
	ptyEventOutput = 0x12
	ptyEventExit   = 0x13
	ptyEventError  = 0x14

	ptyOpOpen   = 0x01
	ptyOpInput  = 0x02
	ptyOpResize = 0x03
	ptyOpSignal = 0x04
	ptyOpClose  = 0x05
)

type Service struct {
	Config      *config.Config
	state       *VState
	replay      *krb.ReplayWindow
	startTime   time.Time
	nextSeq     uint32
	nextPtyID   uint32
	privKey     *krb.RSAKey
	clientCerts map[string]*krb.Certificate
	httpServer  *http.Server
}

func NewService(configPath string) *Service {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("load config: %v", err))
	}
	kv, _ := krb.LoadKey8(cfg.KVPath, "v-kv")
	var priv *krb.RSAKey
	if cfg.PrivKeyPath != "" {
		priv, _ = krb.LoadRSAPrivateKey(cfg.PrivKeyPath)
	}
	s := &Service{
		Config:      cfg,
		state:       &VState{SeqNum: 1, IDV: cfg.NodeID, Kv: kv, Sessions: make(map[string]*SessionContext)},
		replay:      krb.NewReplayWindow(1024),
		startTime:   time.Now(),
		privKey:     priv,
		clientCerts: make(map[string]*krb.Certificate),
	}
	for _, item := range cfg.ClientDB {
		if item.CertPath == "" {
			continue
		}
		cert, err := krb.CertLoad(item.CertPath)
		if err != nil {
			continue
		}
		s.clientCerts[item.ID] = cert
	}
	return s
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
	log.Printf("[V] listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[V] accept failed: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		s.state.mu.RLock()
		active := len(s.state.Sessions)
		s.state.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node_id":               s.Config.NodeID,
			"uptime_s":              int64(time.Since(s.startTime).Seconds()),
			"active_sessions":       active,
			"total_pty_frames":      atomic.LoadUint32(&s.nextSeq),
			"total_rejected_frames": 0,
		})
	})
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		s.state.mu.RLock()
		defer s.state.mu.RUnlock()
		out := make([]map[string]any, 0, len(s.state.Sessions))
		for _, sess := range s.state.Sessions {
			sum := krb.Hash256(sess.KeyCV[:])
			out = append(out, map[string]any{
				"client_id":      sess.IDClient,
				"client_ip":      sess.ADc,
				"k_cv_sha256":    hex.EncodeToString(sum[:8]),
				"expire_at":      sess.ExpireAt,
				"last_io_ts":     sess.LastIO.Unix(),
				"total_frames":   sess.TotalFrames,
				"pty_session_id": sess.PtySessionID,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sessions": out})
	})
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("[V] webui listening on %s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[V] webui failed: %v", err)
	}
}

func (s *Service) nextServerSeq() uint32 {
	return atomic.AddUint32(&s.nextSeq, 1)
}

func (s *Service) nextSessionID() uint32 {
	return atomic.AddUint32(&s.nextPtyID, 1)
}

func (s *Service) handleConnection(conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var writeMu sync.Mutex
	sendPacket := func(msgType uint8, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return krb.WritePacket(conn, msgType, s.nextServerSeq(), uint32(time.Now().Unix()), payload)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var authed bool
	var current *SessionContext
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
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

		switch h.MsgType {
		case krb.MsgAPReq:
			if authed {
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
				return
			}
			respPayload, sess, errCode := s.handleAPReq(ctx, h, payload, sendPacket)
			if errCode != krb.KRBOK {
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(errCode))
				return
			}
			authed = true
			current = sess
			if err := sendPacket(krb.MsgAPRep, respPayload); err != nil {
				return
			}
		case krb.MsgApp:
			if !authed || current == nil {
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound))
				return
			}
			respType, respPayload, respCode := s.handleAPPReq(h, payload, current, sendPacket)
			if respCode != krb.KRBOK {
				if respType == krb.MsgErr {
					_ = sendPacket(krb.MsgErr, respPayload)
				} else {
					_ = sendPacket(respType, respPayload)
				}
				return
			}
			if err := sendPacket(respType, respPayload); err != nil {
				return
			}
			if current != nil && current.Closed {
				return
			}
			if respType == krb.MsgApp {
				continue
			}
			return
		default:
			_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
			return
		}
	}
}

func (s *Service) handleAPReq(connCtx context.Context, h krb.KerHeader, payload []byte, sendPacket func(uint8, []byte) error) ([]byte, *SessionContext, int32) {
	req, code := krb.ParseAPReqPayload(payload)
	if code != krb.KRBOK {
		return nil, nil, code
	}
	ticket, code := krb.DecodeTicketV(req.TicketV, s.state.Kv)
	if code != krb.KRBOK {
		return nil, nil, code
	}
	if ticket.IDV.Len > 0 && string(ticket.IDV.Data) != s.state.IDV {
		return nil, nil, krb.ErrTicketInvalid
	}
	if uint32(time.Now().Unix()) > ticket.TS4+ticket.Lifetime {
		return nil, nil, krb.ErrTicketExpired
	}
	auth, code := krb.DecodeAuthenticatorCV(req.AuthCipher, ticket.KeyCV)
	if code != krb.KRBOK {
		return nil, nil, code
	}
	if string(auth.IDClient.Data) != string(ticket.IDClient.Data) {
		return nil, nil, krb.ErrAuthMismatch
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc {
		return nil, nil, krb.ErrADMismatch
	}

	sess := &SessionContext{
		IDClient:     string(ticket.IDClient.Data),
		ADc:          ticket.ADc,
		KeyCV:        ticket.KeyCV,
		ExpireAt:     ticket.TS4 + ticket.Lifetime,
		PtySessionID: 0,
		LastIO:       time.Now(),
	}
	sess.Ctx, sess.Cancel = context.WithCancel(connCtx)
	s.state.mu.Lock()
	s.state.Sessions[sess.IDClient] = sess
	s.state.mu.Unlock()

	resp, code := krb.BuildAPRepPayload(auth.TS5, ticket.KeyCV)
	if code != krb.KRBOK {
		return nil, nil, code
	}
	return resp, sess, krb.KRBOK
}

func (s *Service) handleAPPReq(h krb.KerHeader, payload []byte, current *SessionContext, sendPacket func(uint8, []byte) error) (uint8, []byte, int32) {
	req, code := krb.ParseAPPReqPayload(payload)
	if code != krb.KRBOK {
		return krb.MsgErr, krb.BuildErrorPayload(code), code
	}
	if req.IDClient.Len > 0 && string(req.IDClient.Data) != current.IDClient {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertIDMismatch), krb.ErrCertIDMismatch
	}
	if uint32(time.Now().Unix()) > current.ExpireAt {
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), krb.ErrTicketExpired
	}

	if cert := s.clientCerts[current.IDClient]; cert != nil {
		pub, err := cert.PublicKeyRSA()
		if err != nil {
			return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertSigInvalid), krb.ErrCertSigInvalid
		}
		if code := krb.VerifyCipherSignature(h.SeqNum, req.Cipher, req.RSASignC, pub); code != krb.KRBOK {
			return krb.MsgErr, krb.BuildErrorPayload(code), code
		}
	}

	plain, code := krb.DecryptAPPReqPlain(req.Cipher, current.KeyCV)
	if code != krb.KRBOK {
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("decrypt failed")), code
	}
	atomic.AddUint64(&current.TotalFrames, 1)
	current.LastIO = time.Now()

	switch plain.PtyOp {
	case ptyOpOpen:
		term, cols, rows, code := parsePtyOpenPayload(plain.Payload)
		if code != krb.KRBOK {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("bad open payload")), code
		}
		if current.PTY != nil {
			_ = current.PTY.Close()
		}
		ptySession, startCode := startPTYSession(term, cols, rows)
		if startCode != krb.KRBOK || ptySession == nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("pty start failed")), startCode
		}
		current.PTY = ptySession
		current.PtySessionID = s.nextSessionID()
		if current.Cancel != nil {
			go func(sess *SessionContext) {
				<-sess.Ctx.Done()
				if sess.PTY != nil {
					_ = sess.PTY.Close()
				}
			}(current)
		}
		go s.streamPTYOutput(current, sendPacket)
		out := []byte(fmt.Sprintf("open ok: %s", current.IDClient))
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventOpenOK, current.PtySessionID, -1, out), krb.KRBOK
	case ptyOpInput:
		if current.PTY == nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrSessionNotFound
		}
		if _, err := current.PTY.PTY.Write(plain.Payload); err != nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("pty write failed")), krb.ErrSocketSend
		}
		out := append([]byte("echo: "), plain.Payload...)
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventOutput, current.PtySessionID, -1, out), krb.KRBOK
	case ptyOpResize:
		if current.PTY == nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrSessionNotFound
		}
		cols, rows, code := parsePtyResizePayload(plain.Payload)
		if code != krb.KRBOK {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("bad resize payload")), code
		}
		if err := current.PTY.Resize(cols, rows); err != nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("resize failed")), krb.ErrSessionNotFound
		}
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventOutput, current.PtySessionID, -1, []byte("resize ok")), krb.KRBOK
	case ptyOpSignal:
		if current.PTY == nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrSessionNotFound
		}
		sig, code := parsePtySignalPayload(plain.Payload)
		if code != krb.KRBOK {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("bad signal payload")), code
		}
		if err := current.PTY.Signal(sig); err != nil {
			return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("signal failed")), krb.ErrSessionNotFound
		}
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventOutput, current.PtySessionID, -1, []byte("signal ok")), krb.KRBOK
	case ptyOpClose:
		if current.Cancel != nil {
			current.Cancel()
		}
		if current.PTY != nil {
			_ = current.PTY.Close()
		}
		s.state.mu.Lock()
		delete(s.state.Sessions, current.IDClient)
		s.state.mu.Unlock()
		current.Closed = true
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventExit, current.PtySessionID, 0, []byte("bye")), krb.KRBOK
	default:
		return krb.MsgApp, s.buildAPPRep(current, h.SeqNum, ptyEventError, current.PtySessionID, -1, []byte("invalid pty op")), krb.ErrMsgTypeInvalid
	}
}

func (s *Service) streamPTYOutput(current *SessionContext, sendPacket func(uint8, []byte) error) {
	if current == nil || current.PTY == nil || current.Ctx == nil {
		return
	}
	ch := make(chan []byte, 16)
	go current.PTY.ReadAll(ch, current.Ctx.Done())
	for data := range ch {
		if len(data) == 0 {
			continue
		}
		atomic.AddUint64(&current.TotalFrames, 1)
		current.LastIO = time.Now()
		rep := s.buildAPPRep(current, s.nextServerSeq(), ptyEventOutput, current.PtySessionID, -1, data)
		_ = sendPacket(krb.MsgApp, rep)
	}
	if current.Closed {
		return
	}
	rep := s.buildAPPRep(current, s.nextServerSeq(), ptyEventExit, current.PtySessionID, 0, nil)
	_ = sendPacket(krb.MsgApp, rep)
}

func parsePtyOpenPayload(raw []byte) (string, uint16, uint16, int32) {
	if len(raw) < 2 {
		return "", 0, 0, krb.ErrTicketInvalid
	}
	termLen := int(binary.BigEndian.Uint16(raw[:2]))
	if len(raw) < 2+termLen+4 {
		return "", 0, 0, krb.ErrTicketInvalid
	}
	term := string(raw[2 : 2+termLen])
	cols := binary.BigEndian.Uint16(raw[2+termLen : 2+termLen+2])
	rows := binary.BigEndian.Uint16(raw[2+termLen+2 : 2+termLen+4])
	return term, cols, rows, krb.KRBOK
}

func parsePtyResizePayload(raw []byte) (uint16, uint16, int32) {
	if len(raw) < 4 {
		return 0, 0, krb.ErrTicketInvalid
	}
	return binary.BigEndian.Uint16(raw[:2]), binary.BigEndian.Uint16(raw[2:4]), krb.KRBOK
}

func parsePtySignalPayload(raw []byte) (uint8, int32) {
	if len(raw) < 1 {
		return 0, krb.ErrTicketInvalid
	}
	return raw[0], krb.KRBOK
}

func (s *Service) buildAPPRep(current *SessionContext, seq uint32, event uint8, ptySessionID uint32, exitCode int32, payload []byte) []byte {
	signFn := func(cipherData []byte) [256]byte {
		raw := make([]byte, 4+len(cipherData))
		copy(raw[:4], krb.Uint32ToBytes(seq))
		copy(raw[4:], cipherData)
		sig, _ := krb.SignSHA256(raw, s.privKey)
		return sig
	}
	wire, _ := krb.BuildAPPRepPayload(event, ptySessionID, exitCode, payload, current.KeyCV, signFn)
	return wire
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	return krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
}
