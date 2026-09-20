package main

// frame is a passthrough marker type used by rawCodec for RPCs the proxy does
// not need to understand: it carries the raw wire bytes untouched, so any
// method not explicitly registered on this server flows through byte-for-byte
// via the UnknownServiceHandler. See proxy.go for which ones those are.
type frame struct {
	payload []byte
}
