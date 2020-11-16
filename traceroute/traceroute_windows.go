package traceroute

import (
	"bufio"
	"context"
	"net"
	"os/exec"
)

func (t *Tracer) Trace(ctx context.Context, dest net.IP, c chan Hop) error {
	cmd := exec.CommandContext(ctx, "tracert", "-d", dest.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s := bufio.NewScanner(stdout)
	for s.Scan() {
		if hop, ok := parseTracertLine(s.Text()); ok {
			c <- hop
		}
	}
	return cmd.Wait()
}
