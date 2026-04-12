"""
Unit tests for core components: packet serialization, peer registry,
exit policy, and circuit building.
"""

import time
import pytest

from ygg_tunnel.packet import MsgType, Packet
from ygg_tunnel.peers import PeerInfo, PeerRegistry
from ygg_tunnel.exit_policy import ExitPolicy
from ygg_tunnel.keys import NodeIdentity
from ygg_tunnel.circuit import Circuit, build_onion_connect
from ygg_tunnel.crypto import encrypt_for, decrypt_layer


# ---------------------------------------------------------------------------
# Packet serialization
# ---------------------------------------------------------------------------

class TestPacket:
    def test_roundtrip_onion_relay(self):
        pkt = Packet(MsgType.ONION_RELAY, "[200:abcd::1]:9051", b"\xde\xad\xbe\xef" * 8)
        assert Packet.from_bytes(pkt.to_bytes()) == pkt

    def test_roundtrip_empty_next_hop(self):
        pkt = Packet(MsgType.ONION_EXIT, "", b"hello world")
        assert Packet.from_bytes(pkt.to_bytes()) == pkt

    def test_roundtrip_ipv4_hop(self):
        pkt = Packet(MsgType.ONION_RELAY, "127.0.0.1:19001", b"payload")
        assert Packet.from_bytes(pkt.to_bytes()) == pkt

    def test_roundtrip_udp_types(self):
        for msg_type in (MsgType.ONION_UDP_EXIT, MsgType.ONION_UDP_RESP):
            pkt = Packet(msg_type, "", b"udp data here")
            assert Packet.from_bytes(pkt.to_bytes()) == pkt

    def test_from_bytes_too_short_raises(self):
        with pytest.raises(ValueError):
            Packet.from_bytes(b"\x01\x11")   # truncated header

    def test_wrong_version_raises(self):
        pkt = Packet(MsgType.ONION_RELAY, "", b"x")
        raw = bytearray(pkt.to_bytes())
        raw[0] = 0xFF   # corrupt version byte
        with pytest.raises(ValueError):
            Packet.from_bytes(bytes(raw))

    def test_is_onion(self):
        assert Packet(MsgType.ONION_RELAY, "", b"").msg_type.is_onion()
        assert Packet(MsgType.ONION_EXIT, "", b"").msg_type.is_onion()
        assert Packet(MsgType.ONION_UDP_EXIT, "", b"").msg_type.is_onion()
        assert not Packet(MsgType.RELAY, "", b"").msg_type.is_onion()


# ---------------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------------

def _make_peer(addr: str, modes=None, port: int = 9051) -> PeerInfo:
    ident = NodeIdentity.generate()
    return PeerInfo(
        addr=addr,
        pubkey_enc=ident.public_key_b64,
        pubkey_sign=ident.verify_key_b64,
        modes=modes or ["relay"],
        port=port,
    )


class TestPeerRegistry:
    def test_add_and_len(self):
        reg = PeerRegistry()
        reg.add(_make_peer("200::1"))
        reg.add(_make_peer("200::2"))
        assert len(reg) == 2

    def test_add_same_key_updates(self):
        reg = PeerRegistry()
        p = _make_peer("200::1")
        reg.add(p)
        reg.add(p)
        assert len(reg) == 1

    def test_remove_by_addr(self):
        reg = PeerRegistry()
        reg.add(_make_peer("200::1"))
        reg.add(_make_peer("200::2"))
        reg.remove("200::1")
        assert len(reg) == 1
        assert reg.all()[0].addr == "200::2"

    def test_relays_and_exits(self):
        reg = PeerRegistry()
        reg.add(_make_peer("200::1", modes=["relay"]))
        reg.add(_make_peer("200::2", modes=["exit"]))
        reg.add(_make_peer("200::3", modes=["relay", "exit"]))
        assert len(reg.relays()) == 2   # 200::1 and 200::3
        assert len(reg.exits()) == 2    # 200::2 and 200::3

    def test_update_from_list_returns_new_count(self):
        reg = PeerRegistry()
        reg.add(_make_peer("200::1"))
        new = reg.update_from_list([_make_peer("200::1"), _make_peer("200::2")])
        assert new == 1

    def test_mark_seen_resets_failures(self):
        reg = PeerRegistry()
        p = _make_peer("200::1")
        reg.add(p)
        key = f"{p.addr}:{p.port}"
        reg.mark_failed(key)
        reg.mark_failed(key)
        reg.mark_seen(key)
        assert reg._fail_counts[key] == 0

    def test_mark_failed_increments(self):
        reg = PeerRegistry()
        p = _make_peer("200::1")
        reg.add(p)
        key = f"{p.addr}:{p.port}"
        assert reg.mark_failed(key) == 1
        assert reg.mark_failed(key) == 2

    def test_persistence_roundtrip(self, tmp_path):
        path = tmp_path / "peers.json"
        reg = PeerRegistry()
        reg.add(_make_peer("200::1", modes=["relay"]))
        reg.add(_make_peer("200::2", modes=["exit"]))
        reg.save(path)

        reg2 = PeerRegistry()
        reg2.load(path)
        assert len(reg2) == 2
        addrs = {p.addr for p in reg2.all()}
        assert addrs == {"200::1", "200::2"}


# ---------------------------------------------------------------------------
# Exit policy
# ---------------------------------------------------------------------------

class TestExitPolicy:
    def test_default_allows_web_ports(self):
        pol = ExitPolicy.default()
        assert pol.allows(80)
        assert pol.allows(443)
        assert pol.allows(8080)
        assert pol.allows(8443)

    def test_default_blocks_other_ports(self):
        pol = ExitPolicy.default()
        assert not pol.allows(22)
        assert not pol.allows(25)
        assert not pol.allows(3306)

    def test_allow_all(self):
        pol = ExitPolicy.allow_all_ports()
        for port in (22, 80, 443, 1234, 65535):
            assert pol.allows(port)

    def test_deny_all(self):
        pol = ExitPolicy.from_string("")
        for port in (80, 443, 22):
            assert not pol.allows(port)

    def test_custom_ports(self):
        pol = ExitPolicy.from_string("22,8080")
        assert pol.allows(22)
        assert pol.allows(8080)
        assert not pol.allows(80)
        assert not pol.allows(443)

    def test_wildcard_string(self):
        pol = ExitPolicy.from_string("*")
        assert pol.allow_all
        assert pol.allows(1)

    def test_roundtrip_str(self):
        pol = ExitPolicy.from_string("80,443,8080")
        assert ExitPolicy.from_string(str(pol)).ports == pol.ports


# ---------------------------------------------------------------------------
# Circuit — onion layer count
# ---------------------------------------------------------------------------

class TestCircuit:
    def _make_circuit(self, n: int) -> Circuit:
        peers = [_make_peer(f"200::{i}", modes=["relay"] if i < n else ["exit"], port=9050 + i)
                 for i in range(1, n + 1)]
        peers[-1] = _make_peer(f"200::{n}", modes=["exit"], port=9050 + n)
        return Circuit(hops=peers)

    def test_guard_and_exit_properties(self):
        c = self._make_circuit(3)
        assert c.guard is c.hops[0]
        assert c.exit_node is c.hops[-1]

    def test_describe_3_hop(self):
        c = self._make_circuit(3)
        desc = c.describe()
        assert "Guard=" in desc
        assert "Middle=" in desc
        assert "Exit=" in desc

    def test_describe_2_hop(self):
        c = self._make_circuit(2)
        desc = c.describe()
        assert "Guard=" in desc
        assert "Exit=" in desc
        assert "Middle" not in desc

    def test_not_expired_immediately(self):
        c = self._make_circuit(3)
        assert not c.is_expired()

    def test_onion_packet_outermost_is_relay(self):
        c = self._make_circuit(3)
        pkt = build_onion_connect("example.com", 80, c)
        assert pkt.msg_type == MsgType.ONION_RELAY

    def test_onion_decrypt_chain(self):
        """Each hop can peel its layer and get the next inner packet."""
        identities = [NodeIdentity.generate() for _ in range(3)]
        peers = [
            PeerInfo(f"200::{i+1}", id_.public_key_b64, id_.verify_key_b64,
                     ["relay"] if i < 2 else ["exit"], port=9051 + i)
            for i, id_ in enumerate(identities)
        ]
        circuit = Circuit(hops=peers)
        outer = build_onion_connect("example.com", 443, circuit)

        # Guard peels outer layer
        inner_bytes = decrypt_layer(outer.payload, identities[0].private_key)
        mid_pkt = Packet.from_bytes(inner_bytes)
        assert mid_pkt.msg_type == MsgType.ONION_RELAY

        # Middle peels second layer
        inner_bytes2 = decrypt_layer(mid_pkt.payload, identities[1].private_key)
        exit_pkt = Packet.from_bytes(inner_bytes2)
        assert exit_pkt.msg_type == MsgType.ONION_EXIT

        # Exit decrypts innermost to get target
        target_bytes = decrypt_layer(exit_pkt.payload, identities[2].private_key)
        assert target_bytes == b"example.com:443\n"
