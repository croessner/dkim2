bind_socket = "0.0.0.0:11332";
milter = true;
timeout = 120s;
upstream "local" {
  default = true;
  self_scan = true;
}
