package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

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
