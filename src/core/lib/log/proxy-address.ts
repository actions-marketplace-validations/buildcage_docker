/**
 * The gateway the build reaches the proxy and its resolver through, and the
 * address CoreDNS answers every name with. A connection sent there was named
 * rather than addressed, so its destination says nothing about which name.
 *
 * This is the inspect engine's network gateway, declared in its cni.conflist
 * and echoed into its haproxy config generator as GATEWAY=; neither can import
 * this, so the test beside this holds all three to the same value.
 */
export const PROXY_ADDRESS = "172.20.0.1";
