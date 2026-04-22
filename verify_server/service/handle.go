package service

import "net"

func (s *Service) handleConnection(conn net.Conn) {
	defer conn.Close()
	// 处理连接的逻辑，例如读取数据、验证身份等
	// 这里可以根据实际需求实现具体的处理逻辑
}
