package service

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"security-project/common/krb"
)

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
