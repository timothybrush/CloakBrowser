"""Unit tests for build_launch_options and external humanize helpers."""

import sys
import types
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from cloakbrowser.config import IGNORE_DEFAULT_ARGS


def test_build_launch_options_preserves_current_launch_behaviour():
    """build_launch_options includes the current launch() pre-launch steps."""
    from cloakbrowser.browser import build_launch_options

    proxy_option = {"server": "http://proxy:8080"}
    launch_env = {"CUSTOM": "1", "CLOAKBROWSER_LICENSE_KEY": "cb_key"}

    with (
        patch("cloakbrowser.browser.ensure_binary", return_value="/fake/chrome") as mock_ensure,
        patch(
            "cloakbrowser.browser.maybe_resolve_geoip",
            return_value=("Europe/Berlin", "de-DE", "5.6.7.8"),
        ) as mock_geoip,
        patch(
            "cloakbrowser.browser._resolve_proxy_config",
            return_value=({"proxy": proxy_option}, ["--proxy-server=http://proxy:8080"]),
        ) as mock_proxy,
        patch("cloakbrowser.browser.build_launch_env", return_value=launch_env) as mock_env,
        patch("cloakbrowser.browser._maybe_warn_windows_fonts") as mock_font_warning,
    ):
        opts = build_launch_options(
            headless=False,
            proxy="http://proxy:8080",
            args=["--custom-flag"],
            stealth_args=False,
            timezone="America/New_York",
            locale="en-US",
            geoip=True,
            extension_paths=["/tmp/ext"],
            license_key="cb_key",
            browser_version="148.0.7778.215.4",
            env={"CUSTOM": "1"},
            timeout=1234,
        )

    assert opts["executable_path"] == "/fake/chrome"
    assert opts["headless"] is False
    assert opts["ignore_default_args"] == IGNORE_DEFAULT_ARGS
    assert opts["proxy"] is proxy_option
    assert opts["env"] == launch_env
    assert opts["timeout"] == 1234
    assert "--custom-flag" in opts["args"]
    assert "--proxy-server=http://proxy:8080" in opts["args"]
    assert "--fingerprint-webrtc-ip=5.6.7.8" in opts["args"]
    assert "--fingerprint-timezone=Europe/Berlin" in opts["args"]
    assert "--lang=de-DE" in opts["args"]
    assert "--fingerprint-locale=de-DE" in opts["args"]
    assert "--start-maximized" in opts["args"]

    mock_ensure.assert_called_once_with(
        license_key="cb_key",
        browser_version="148.0.7778.215.4",
        release_channel=None,
    )
    mock_geoip.assert_called_once_with(True, "http://proxy:8080", "America/New_York", "en-US", ANY)
    mock_proxy.assert_called_once_with("http://proxy:8080")
    mock_env.assert_called_once_with("cb_key", user_env={"CUSTOM": "1"}, status_file=ANY)
    mock_font_warning.assert_called_once_with(opts["args"])


def test_build_launch_options_threads_suppress_maximize():
    """_suppress_maximize disables --start-maximized."""
    from cloakbrowser.browser import build_launch_options

    with (
        patch("cloakbrowser.browser.ensure_binary", return_value="/fake/chrome"),
        patch("cloakbrowser.browser.build_launch_env", return_value=None),
        patch("cloakbrowser.browser._maybe_warn_windows_fonts"),
    ):
        opts = build_launch_options(stealth_args=False, _suppress_maximize=True)

    assert "--start-maximized" not in opts["args"]


def test_guard_browser_installs_guard_from_options_env():
    """guard_browser reads the denial path build_launch_options put in env."""
    from cloakbrowser.browser import guard_browser
    from cloakbrowser.license import LICENSE_STATUS_FILE_ENV

    browser = MagicMock()
    with patch("cloakbrowser.browser._install_license_guard") as mock_guard:
        guard_browser(browser, {"env": {LICENSE_STATUS_FILE_ENV: "/tmp/d.json"}})

    mock_guard.assert_called_once_with(browser, "/tmp/d.json")
    assert browser._cloak_denial_path == "/tmp/d.json"


def test_guard_browser_async_uses_async_guard():
    from cloakbrowser.browser import guard_browser_async
    from cloakbrowser.license import LICENSE_STATUS_FILE_ENV

    browser = MagicMock()
    with patch("cloakbrowser.browser._install_license_guard_async") as mock_guard:
        guard_browser_async(browser, {"env": {LICENSE_STATUS_FILE_ENV: "/tmp/d.json"}})

    mock_guard.assert_called_once_with(browser, "/tmp/d.json")


def test_license_error_maps_launch_failure():
    """A denial during launch (binary exit 76 in Playwright's launch log) maps to
    CloakBrowserLicenseError; any other error maps to None."""
    from cloakbrowser import license_error_from
    from cloakbrowser.license import CloakBrowserLicenseError

    denied = Exception(
        "BrowserType.launch: Target page, context or browser has been closed\n"
        "  - [pid=1] <process did exit: exitCode=76, signal=null>"
    )
    assert isinstance(license_error_from(denied), CloakBrowserLicenseError)
    assert license_error_from(Exception("net::ERR_PROXY_CONNECTION_FAILED")) is None


def test_license_error_from_falls_back_to_denial_file(tmp_path):
    """No exit code in the text -> read the launch's denial file (JS/.NET parity)."""
    from cloakbrowser import license_error_from
    from cloakbrowser.license import LICENSE_STATUS_FILE_ENV, CloakBrowserLicenseError

    closed = Exception("BrowserType.launch: Target page, context or browser has been closed")
    opts = {"env": {LICENSE_STATUS_FILE_ENV: str(tmp_path / "d.json")}}
    assert license_error_from(closed, opts) is None  # no file -> genuine error
    (tmp_path / "d.json").write_text("76")
    assert license_error_from(closed) is None  # no options -> text only
    assert isinstance(license_error_from(closed, opts), CloakBrowserLicenseError)


def test_license_denial_reads_stashed_path(tmp_path):
    """license_denial checks without a browser call; repeat calls keep the answer."""
    from cloakbrowser import license_denial
    from cloakbrowser.license import CloakBrowserLicenseError

    class Obj:
        pass

    ctx = Obj()
    assert license_denial(ctx) is None  # nothing stashed -> no license in play
    ctx._cloak_denial_path = str(tmp_path / "d.json")
    assert license_denial(ctx) is None  # no file -> not denied
    (tmp_path / "d.json").write_text("76")
    assert isinstance(license_denial(ctx), CloakBrowserLicenseError)
    assert isinstance(license_denial(ctx), CloakBrowserLicenseError)  # file consumed, cached


def test_guard_browser_noop_without_license():
    """No key -> no env/denial path -> nothing installed."""
    from cloakbrowser.browser import guard_browser

    with patch("cloakbrowser.browser._install_license_guard") as mock_guard:
        guard_browser(MagicMock(), {"executable_path": "/fake/chrome"})
        guard_browser(MagicMock(), {"env": {"FOO": "1"}})

    mock_guard.assert_not_called()


def test_guard_browser_raises_license_error_on_denial(tmp_path):
    """End to end on a fake browser: a denial file turns the next call's
    failure into CloakBrowserLicenseError."""
    from cloakbrowser.browser import guard_browser
    from cloakbrowser.license import LICENSE_STATUS_FILE_ENV, CloakBrowserLicenseError

    class FakeBrowser:
        def new_page(self):
            raise RuntimeError("Target page, context or browser has been closed")

    denial = tmp_path / "d.json"
    denial.write_text("77")
    browser = FakeBrowser()
    guard_browser(browser, {"env": {LICENSE_STATUS_FILE_ENV: str(denial)}})

    with pytest.raises(CloakBrowserLicenseError):
        browser.new_page()


def test_build_launch_options_removed_backend_raises():
    """Removed kwargs still fail before any launch side effects."""
    from cloakbrowser.browser import build_launch_options

    with pytest.raises(TypeError, match="backend"):
        build_launch_options(backend="patchright")


def test_humanize_browser_patches_existing_browser():
    """humanize_browser resolves config and patches the passed sync browser."""
    from cloakbrowser.browser import humanize_browser

    browser = object()
    cfg = object()
    overrides = {"typing_delay": 12}

    with (
        patch("cloakbrowser.human.config.resolve_config", return_value=cfg) as mock_resolve,
        patch("cloakbrowser.human.patch_browser") as mock_patch,
    ):
        humanize_browser(browser, human_preset="careful", human_config=overrides)

    mock_resolve.assert_called_once_with("careful", overrides)
    mock_patch.assert_called_once_with(browser, cfg)


def test_humanize_browser_async_patches_existing_browser():
    """humanize_browser_async resolves config and patches the passed async browser."""
    from cloakbrowser.browser import humanize_browser_async

    browser = object()
    cfg = object()
    overrides = {"typing_delay": 12}

    with (
        patch("cloakbrowser.human.config.resolve_config", return_value=cfg) as mock_resolve,
        patch("cloakbrowser.human.patch_browser_async") as mock_patch,
    ):
        humanize_browser_async(browser, human_preset="careful", human_config=overrides)

    mock_resolve.assert_called_once_with("careful", overrides)
    mock_patch.assert_called_once_with(browser, cfg)


def test_launch_delegates_to_build_launch_options_and_humanize_browser():
    """launch forwards build_launch_options output directly to Playwright."""
    from cloakbrowser.browser import launch

    launch_opts = {
        "executable_path": "/fake/chrome",
        "headless": True,
        "args": ["--custom-flag"],
        "ignore_default_args": IGNORE_DEFAULT_ARGS,
        "timeout": 1234,
    }
    browser = MagicMock()
    pw = MagicMock()
    pw.chromium.launch.return_value = browser
    launcher = MagicMock()
    launcher.start.return_value = pw
    overrides = {"typing_delay": 12}
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = MagicMock(return_value=launcher)
    playwright = types.ModuleType("playwright")
    playwright.sync_api = sync_api

    with (
        patch.dict(sys.modules, {"playwright": playwright, "playwright.sync_api": sync_api}),
        patch("cloakbrowser.browser.build_launch_options", return_value=launch_opts) as mock_build,
        patch("cloakbrowser.browser.humanize_browser") as mock_humanize,
    ):
        result = launch(
            headless=True,
            proxy="http://proxy:8080",
            args=["--custom-flag"],
            stealth_args=False,
            timezone="Europe/Berlin",
            locale="de-DE",
            geoip=True,
            humanize=True,
            human_preset="careful",
            human_config=overrides,
            extension_paths=["/tmp/ext"],
            license_key="cb_key",
            browser_version="148.0.7778.215.4",
            _suppress_maximize=True,
            timeout=1234,
        )

    mock_build.assert_called_once_with(
        headless=True,
        proxy="http://proxy:8080",
        args=["--custom-flag"],
        stealth_args=False,
        timezone="Europe/Berlin",
        locale="de-DE",
        geoip=True,
        extension_paths=["/tmp/ext"],
        license_key="cb_key",
        browser_version="148.0.7778.215.4",
        release_channel=None,
        _suppress_maximize=True,
        timeout=1234,
    )
    pw.chromium.launch.assert_called_once_with(**launch_opts)
    mock_humanize.assert_called_once_with(browser, "careful", overrides)
    # Proxy given but no Playwright "proxy" option -> it went as --proxy-server (#579).
    browser._impl_obj.on.assert_called_once_with("context", ANY)
    assert result is browser


@pytest.mark.asyncio
async def test_launch_async_delegates_to_build_launch_options():
    """launch_async forwards build_launch_options output directly to Playwright."""
    from cloakbrowser.browser import launch_async

    launch_opts = {
        "executable_path": "/fake/chrome",
        "headless": True,
        "args": ["--custom-flag"],
        "ignore_default_args": IGNORE_DEFAULT_ARGS,
        "proxy": {"server": "http://proxy:8080"},
        "timeout": 1234,
    }
    browser = AsyncMock()
    browser._impl_obj = MagicMock()
    pw = MagicMock()
    pw.chromium.launch = AsyncMock(return_value=browser)
    pw.stop = AsyncMock()
    launcher = MagicMock()
    launcher.start = AsyncMock(return_value=pw)
    async_api = types.ModuleType("playwright.async_api")
    async_api.async_playwright = MagicMock(return_value=launcher)
    playwright = types.ModuleType("playwright")
    playwright.async_api = async_api

    with (
        patch.dict(sys.modules, {"playwright": playwright, "playwright.async_api": async_api}),
        patch("cloakbrowser.browser.build_launch_options", return_value=launch_opts) as mock_build,
    ):
        result = await launch_async(
            headless=True,
            proxy="http://proxy:8080",
            args=["--custom-flag"],
            stealth_args=False,
            timezone="Europe/Berlin",
            locale="de-DE",
            geoip=True,
            extension_paths=["/tmp/ext"],
            license_key="cb_key",
            browser_version="148.0.7778.215.4",
            timeout=1234,
        )

    mock_build.assert_called_once_with(
        headless=True,
        proxy="http://proxy:8080",
        args=["--custom-flag"],
        stealth_args=False,
        timezone="Europe/Berlin",
        locale="de-DE",
        geoip=True,
        extension_paths=["/tmp/ext"],
        license_key="cb_key",
        browser_version="148.0.7778.215.4",
        release_channel=None,
        _suppress_maximize=False,
        timeout=1234,
    )
    pw.chromium.launch.assert_awaited_once_with(**launch_opts)
    # Proxy went through Playwright's own option -> no #579 warning hook.
    browser._impl_obj.on.assert_not_called()
    assert result is browser
