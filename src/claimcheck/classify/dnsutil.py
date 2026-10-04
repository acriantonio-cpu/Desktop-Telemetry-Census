"""CNAME chain resolution (to unmask first-party subdomains that alias to a tracker: 'CNAME cloaking')."""

from __future__ import annotations

from claimcheck.util import normalize_host


def resolve_cname_chain(host: str, timeout: float = 3.0, max_hops: int = 8) -> tuple[list[str], str]:
    """Return (chain_of_targets, error). Empty chain + empty error = the host has no CNAME."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:  # pragma: no cover
        return [], "dnspython not installed"
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    chain: list[str] = []
    name = normalize_host(host)
    for _ in range(max_hops):
        try:
            ans = resolver.resolve(name, "CNAME")
        except dns.resolver.NoAnswer:
            return chain, ""
        except dns.resolver.NXDOMAIN:
            return chain, "nxdomain"
        except dns.exception.Timeout:
            return chain, "timeout"
        except Exception as e:  # noqa: BLE001
            return chain, f"{type(e).__name__}"
        target = normalize_host(str(ans[0].target))
        if not target or target in chain:
            return chain, "cname loop" if target else ""
        chain.append(target)
        name = target
    return chain, ""
