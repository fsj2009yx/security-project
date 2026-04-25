package service

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"security-project/common/krb"
)

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
