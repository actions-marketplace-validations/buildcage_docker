/**
 * The gateway the build reaches the proxy and its resolver through, and the
 * address CoreDNS answers every name with. A connection sent there was named
 * rather than addressed, so its destination says nothing about which name.
 *
 * This is the inspect engine's network gateway, declared in its cni.conflist
 * and echoed into its haproxy config generator as GATEWAY=; neither can import
 * this, so the test beside this holds all three to the same value.
 *
 * It sits at the far end of 198.18.0.0/15, the RFC 2544 benchmarking block:
 * outside Docker's default address pools, so no network Docker allocates can
 * overlap it, and unused by real networks, which it would shadow otherwise.
 */
export const PROXY_ADDRESS = "198.19.255.1";
