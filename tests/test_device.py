"""Device code flow: the initiation request, the polling loop (pending ->
slow_down -> success), persistence, and error handling. No network."""

import pytest

import entrance
from entrance import _device, _foci

OFFICE = "d3590ed6-52b3-4102-aeff-aad2292ab01c"


def _responses(*seq):
    it = iter(seq)
    return lambda url, data: next(it)


def test_device_login_happy_path(monkeypatch):
    init = {
        "device_code": "DC",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://login.microsoft.com/device",
        "interval": 0,
        "expires_in": 900,
        "message": "open the page and enter ABCD-EFGH",
    }
    monkeypatch.setattr(
        _device,
        "_post_token",
        _responses(
            init,
            {"error": "authorization_pending"},
            {"error": "slow_down"},
            {"access_token": "at", "refresh_token": "FRT", "expires_in": 3600},
        ),
    )
    monkeypatch.setattr(_device.time, "sleep", lambda s: None)
    prompts = []
    broker = _device.device_login(OFFICE, frt_store=None, on_prompt=lambda **k: prompts.append(k))
    assert isinstance(broker, entrance.Broker)
    assert broker.refresh_token == "FRT"
    assert prompts[0]["user_code"] == "ABCD-EFGH"
    assert prompts[0]["verification_uri"] == "https://login.microsoft.com/device"


def test_device_login_persists_token(monkeypatch, tmp_path):
    store = str(tmp_path / "frt")
    init = {"device_code": "DC", "user_code": "X", "verification_uri": "u", "interval": 0}
    monkeypatch.setattr(
        _device, "_post_token", _responses(init, {"access_token": "at", "refresh_token": "SAVED"})
    )
    monkeypatch.setattr(_device.time, "sleep", lambda s: None)
    _device.device_login(OFFICE, frt_store=store)
    assert _foci.read_secret(store) == "SAVED"


def test_device_login_client_cannot_use_flow(monkeypatch):
    monkeypatch.setattr(
        _device,
        "_post_token",
        lambda url, data: {"error": "invalid_client", "error_description": "not supported"},
    )
    with pytest.raises(entrance.DeviceCodeError) as e:
        _device.device_login("officehome-id")
    assert e.value.error == "invalid_client"


def test_device_login_declined_is_fatal(monkeypatch):
    init = {"device_code": "DC", "user_code": "X", "verification_uri": "u", "interval": 0}
    monkeypatch.setattr(
        _device,
        "_post_token",
        _responses(init, {"error": "authorization_declined", "error_description": "user said no"}),
    )
    monkeypatch.setattr(_device.time, "sleep", lambda s: None)
    with pytest.raises(entrance.DeviceCodeError, match="authorization_declined"):
        _device.device_login(OFFICE)


def test_foci_login_device_mode_delegates(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        _device,
        "device_login",
        lambda client_id, **kw: captured.update(client_id=client_id, **kw) or "BROKER",
    )
    out = entrance.foci_login(client_id=OFFICE, frt_store=None, device=True, open_browser=True)
    assert out == "BROKER"
    assert captured["client_id"] == OFFICE and captured["open_browser"] is True


def test_foci_login_device_reuses_store_first(monkeypatch, tmp_path):
    store = tmp_path / "frt"
    store.write_text("saved")
    monkeypatch.setattr(_foci, "_post_token", lambda url, data: {"access_token": "at"})
    monkeypatch.setattr(
        _device, "device_login", lambda *a, **k: pytest.fail("should reuse the store")
    )
    broker = entrance.foci_login(client_id=OFFICE, frt_store=str(store), device=True)
    assert broker("x") == "at"
