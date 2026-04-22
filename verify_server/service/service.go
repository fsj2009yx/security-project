package service

import (
	"fmt"
	"net"
	"security-project/verify_server/config"
)

type Service struct {
	Config *config.Config
	SessionContext
}

func NewService() *Service {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}
	return &Service{
		Config: cfg,
	}
}

func NewListener(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}

func (s *Service) run() {
	listener, err := NewListener(s.Config.Port)
	if err != nil {
		panic(fmt.Sprintf("Failed to start listener: %v", err))
	}
	fmt.Printf("Server listening on port %d\n", s.Config.Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		go s.handleConnection(conn)
	}
}
