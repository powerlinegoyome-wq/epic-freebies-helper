# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import time
from collections.abc import Callable
from contextlib import suppress

import pyotp
from loguru import logger
from playwright.async_api import Locator, Page, expect

TOTP_INPUT_SELECTORS = (
    "input[autocomplete='one-time-code']",
    "input[name='code']",
    "input[id*='code']",
    "input[inputmode='numeric']",
    "input[type='tel']",
)
GENERIC_TEXT_INPUT_SELECTORS = ("input[type='text']",)
TOTP_MIN_SECONDS_REMAINING = 12


def _totp_secret_value() -> str | None:
    secret = os.getenv("EPIC_TOTP_SECRET", "").replace(" ", "").strip()
    return secret or None


def totp_login_enabled() -> bool:
    return _totp_secret_value() is not None


async def _current_totp_code(page: Page, *, force_next_window: bool = False) -> str | None:
    secret = _totp_secret_value()
    if not secret:
        return None

    try:
        totp = pyotp.TOTP(secret)
        remaining = totp.interval - (time.time() % totp.interval)
        if force_next_window or remaining < TOTP_MIN_SECONDS_REMAINING:
            logger.warning(
                "Waiting for fresh Epic authenticator TOTP window | reason={} "
                "seconds_until_next={:.1f}",
                "invalid_retry" if force_next_window else "near_expiry",
                remaining,
            )
            await page.wait_for_timeout(int((remaining + 1) * 1000))
            remaining = totp.interval - (time.time() % totp.interval)
        logger.debug("Generated Epic authenticator TOTP code | seconds_remaining={:.1f}", remaining)
        return totp.now()
    except Exception as err:
        logger.error(
            "Failed to generate Epic authenticator TOTP code; EPIC_TOTP_SECRET is likely "
            "not a valid base32 secret | error_type={}",
            type(err).__name__,
        )
        return None


async def _select_authenticator_mfa_method(page: Page) -> bool:
    with suppress(Exception):
        clicked = await page.evaluate(
            """
            () => {
              const normalize = (value) =>
                (value || '').replace(/\\s+/g, ' ').trim().toLowerCase();
              const isVisible = (element) => {
                const rect = element.getBoundingClientRect();
                const style = window.getComputedStyle(element);
                return rect.width > 0 && rect.height > 0 &&
                  style.visibility !== 'hidden' &&
                  style.display !== 'none' &&
                  style.opacity !== '0';
              };
              const preferred = ['authenticator', 'authentication app', 'verification app'];
              const candidates = Array.from(document.querySelectorAll('button,a,label'))
                .filter(isVisible)
                .filter((element) => {
                  const text = normalize(element.innerText || element.textContent);
                  return preferred.some((marker) => text.includes(marker));
                });
              const target = candidates[0];
              if (!target) {
                return false;
              }
              target.click();
              return true;
            }
            """
        )
        if clicked:
            await page.wait_for_timeout(1000)
            return True
    return False


async def _page_has_mfa_signal(page: Page) -> bool:
    with suppress(Exception):
        return await page.evaluate(
            """
            () => {
              const text = (document.body?.innerText || '').toLowerCase();
              const href = window.location.href.toLowerCase();
              const markers = [
                'two-factor',
                'two factor',
                'authentication code',
                'verification code',
                'security code',
                'authenticator',
                'enter code',
              ];
              return href.includes('/id/login/mfa') ||
                markers.some((marker) => text.includes(marker));
            }
            """
        )
    return False


async def _visible_indexes(page: Page, selector: str, limit: int) -> list[int]:
    locator = page.locator(selector)
    indexes: list[int] = []
    count = await locator.count()
    for index in range(count):
        with suppress(Exception):
            if await locator.nth(index).is_visible(timeout=250):
                indexes.append(index)
                if len(indexes) >= limit:
                    break
    return indexes


async def _has_visible_totp_input(page: Page, selectors: tuple[str, ...]) -> bool:
    for selector in selectors:
        if await _visible_indexes(page, selector, limit=1):
            return True
    return False


async def _focus_totp_entry(page: Page) -> bool:
    with suppress(Exception):
        return await page.evaluate(
            """
            () => {
              const isVisible = (element) => {
                const rect = element.getBoundingClientRect();
                const style = window.getComputedStyle(element);
                return rect.width > 0 && rect.height > 0 &&
                  style.visibility !== 'hidden' &&
                  style.display !== 'none' &&
                  style.opacity !== '0';
              };
              const editables = Array.from(document.querySelectorAll(
                "input, textarea, [contenteditable='true'], [role='textbox']"
              )).filter(isVisible);
              const narrowEditables = editables.filter((element) => {
                const rect = element.getBoundingClientRect();
                return rect.width >= 24 && rect.width <= 90 &&
                  rect.height >= 24 && rect.height <= 90;
              });
              const target = editables.find((element) => {
                const marker = [
                  element.getAttribute('autocomplete'),
                  element.getAttribute('name'),
                  element.getAttribute('id'),
                  element.getAttribute('inputmode'),
                  element.getAttribute('aria-label'),
                ].join(' ').toLowerCase();
                const isCodeField = marker.includes('code') ||
                  marker.includes('numeric') ||
                  marker.includes('one-time');
                return isCodeField ||
                  (narrowEditables.length >= 6 && narrowEditables.includes(element));
              });
              if (!target) {
                return false;
              }
              target.style.setProperty('-webkit-text-security', 'disc', 'important');
              target.style.setProperty('color', 'transparent', 'important');
              target.style.setProperty('caret-color', 'transparent', 'important');
              target.click();
              return true;
            }
            """
        )
    return False


async def _mask_totp_input(field: Locator) -> bool:
    try:
        await field.evaluate(
            """
            (element) => {
              element.style.setProperty('-webkit-text-security', 'disc', 'important');
              element.style.setProperty('color', 'transparent', 'important');
              element.style.setProperty('caret-color', 'transparent', 'important');
            }
            """
        )
        return True
    except Exception as err:
        logger.error(
            "Could not mask Epic authenticator TOTP input before filling | error_type={}",
            type(err).__name__,
        )
        return False


async def _clear_totp_entry(page: Page) -> None:
    focused = False
    with suppress(Exception):
        focused = await page.evaluate(
            """
            () => {
              const isVisible = (element) => {
                const rect = element.getBoundingClientRect();
                const style = window.getComputedStyle(element);
                return rect.width > 0 && rect.height > 0 &&
                  style.visibility !== 'hidden' &&
                  style.display !== 'none' &&
                  style.opacity !== '0';
              };
              const candidates = Array.from(document.querySelectorAll(
                "input, [contenteditable='true'], [role='textbox']"
              ))
                .filter(isVisible)
                .filter((element) => {
                  const rect = element.getBoundingClientRect();
                  const marker = [
                    element.getAttribute('autocomplete'),
                    element.getAttribute('name'),
                    element.getAttribute('id'),
                    element.getAttribute('inputmode'),
                    element.getAttribute('type'),
                    element.getAttribute('aria-label'),
                  ].join(' ').toLowerCase();
                  const looksLikeCodeBox = rect.width >= 20 && rect.width <= 120 &&
                    rect.height >= 20 && rect.height <= 120;
                  return looksLikeCodeBox ||
                    marker.includes('code') ||
                    marker.includes('numeric') ||
                    marker.includes('one-time');
                });

              for (const element of candidates) {
                if ('value' in element) {
                  element.value = '';
                  element.dispatchEvent(new Event('input', { bubbles: true }));
                  element.dispatchEvent(new Event('change', { bubbles: true }));
                } else if (element.isContentEditable) {
                  element.textContent = '';
                  element.dispatchEvent(new Event('input', { bubbles: true }));
                }
              }

              const target = candidates[0];
              if (target) {
                target.click();
                return true;
              }
              return false;
            }
            """
        )

    if focused:
        with suppress(Exception):
            await page.keyboard.press("Control+A")
            await page.keyboard.press("Backspace")


async def redact_totp_inputs(page: Page) -> None:
    if not totp_login_enabled():
        return
    if await _page_has_mfa_signal(page):
        await _clear_totp_entry(page)


async def _wait_for_totp_input(page: Page, timeout_ms: int = 20000) -> bool:
    deadline = time.monotonic() + timeout_ms / 1000

    while time.monotonic() < deadline:
        await _select_authenticator_mfa_method(page)

        if await _has_visible_totp_input(page, TOTP_INPUT_SELECTORS):
            return True

        if await _page_has_mfa_signal(page) and await _has_visible_totp_input(
            page, GENERIC_TEXT_INPUT_SELECTORS
        ):
            return True

        if await _page_has_mfa_signal(page) and await _focus_totp_entry(page):
            return True

        await page.wait_for_timeout(500)

    return False


async def submit_totp_challenge(
    page: Page, *, force_next_code: bool = False, before_submit: Callable[[], None] | None = None
) -> bool:
    if not totp_login_enabled():
        return False

    if not await _wait_for_totp_input(page):
        logger.error("Could not find Epic authenticator 2FA code input after waiting")
        return False

    await _clear_totp_entry(page)

    code = await _current_totp_code(page, force_next_window=force_next_code)
    if not code:
        logger.error(
            "Epic account requires authenticator 2FA, but no valid TOTP code could be "
            "generated. Set EPIC_TOTP_SECRET to a valid base32 authenticator secret."
        )
        return False

    # Focus the first input box
    focused = await _focus_totp_entry(page)
    await page.wait_for_timeout(200)

    # Primary entry: Type digits with real keyboard events so React controlled inputs auto-advance
    await page.keyboard.type(code, delay=120)
    await page.wait_for_timeout(400)

    # Check how many digits were entered across the 6 boxes
    filled_values = await page.evaluate(
        """
        () => {
          const isVisible = (el) => {
            const r = el.getBoundingClientRect();
            const s = window.getComputedStyle(el);
            return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
          };
          const inputs = Array.from(document.querySelectorAll("input, [contenteditable='true'], [role='textbox']")).filter(isVisible);
          const narrow = inputs.filter((el) => {
            const r = el.getBoundingClientRect();
            return r.width >= 20 && r.width <= 120 && r.height >= 20 && r.height <= 120;
          });
          return narrow.map((el) => el.value || el.textContent || '');
        }
        """
    )
    entered = "".join(filled_values)
    logger.debug("TOTP input check: entered='{}', expected_len={}", entered, len(code))

    # If keyboard typing did not fill all boxes, fill individually using React prototype value setter
    if entered != code:
        logger.warning(
            "Keyboard typing entered {!r} (expected length {}); applying React-compatible synthetic input dispatch",
            entered,
            len(code),
        )
        await page.evaluate(
            """
            (code) => {
              const isVisible = (el) => {
                const r = el.getBoundingClientRect();
                const s = window.getComputedStyle(el);
                return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
              };
              const inputs = Array.from(document.querySelectorAll("input, [contenteditable='true'], [role='textbox']")).filter(isVisible);
              const narrow = inputs.filter((el) => {
                const r = el.getBoundingClientRect();
                return r.width >= 20 && r.width <= 120 && r.height >= 20 && r.height <= 120;
              });

              const proto = window.HTMLInputElement.prototype;
              const nativeSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;

              if (narrow.length >= code.length) {
                for (let i = 0; i < code.length; i++) {
                  const el = narrow[i];
                  if (nativeSetter) {
                    nativeSetter.call(el, code[i]);
                  } else {
                    el.value = code[i];
                  }
                  el.dispatchEvent(new Event('input', { bubbles: true }));
                  el.dispatchEvent(new Event('change', { bubbles: true }));
                }
              } else {
                const single = inputs.find((el) => {
                  const m = [el.name, el.id, el.getAttribute('autocomplete'), el.getAttribute('inputmode')].join(' ').toLowerCase();
                  return m.includes('code') || m.includes('numeric') || m.includes('one-time');
                }) || inputs[0];
                if (single) {
                  if (nativeSetter) {
                    nativeSetter.call(single, code);
                  } else {
                    single.value = code;
                  }
                  single.dispatchEvent(new Event('input', { bubbles: true }));
                  single.dispatchEvent(new Event('change', { bubbles: true }));
                }
              }
            }
            """,
            code,
        )
        await page.wait_for_timeout(300)

    # Mask the inputs for visual security (screenshots)
    with suppress(Exception):
        await page.evaluate(
            """
            () => {
              const inputs = document.querySelectorAll("input, [contenteditable='true'], [role='textbox']");
              for (const el of inputs) {
                el.style.setProperty('-webkit-text-security', 'disc', 'important');
                el.style.setProperty('color', 'transparent', 'important');
                el.style.setProperty('caret-color', 'transparent', 'important');
              }
            }
            """
        )

    if before_submit:
        before_submit()

    # Locate submit/continue button
    submit_button = None
    for selector in (
        "#continue",
        "button[type='submit']",
        "button:has-text('Continue')",
        "button:has-text('Devam')",
        "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'continue')]",
        "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'verify')]",
        "#sign-in",
    ):
        with suppress(Exception):
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=1000):
                submit_button = locator
                break

    clicked = False
    if submit_button is not None:
        # Wait up to 6 seconds for React to validate the 6 digits and enable the button
        for _ in range(12):
            if await submit_button.is_enabled():
                break
            await page.wait_for_timeout(500)

        if await submit_button.is_enabled():
            with suppress(Exception):
                await submit_button.click(timeout=3000)
                clicked = True
                logger.success("Clicked enabled Epic authenticator 2FA submit button")
        else:
            logger.warning("Continue button still disabled after waiting; attempting forced submission via JS and Enter")
            with suppress(Exception):
                js_ok = await page.evaluate(
                    """
                    () => {
                      const btn = document.querySelector("#continue, button[type='submit']") ||
                        Array.from(document.querySelectorAll("button")).find(b => {
                          const t = (b.innerText || b.textContent || '').toLowerCase();
                          return t.includes('continue') || t.includes('verify');
                        });
                      if (btn) {
                        btn.removeAttribute('disabled');
                        btn.disabled = false;
                        btn.click();
                        return true;
                      }
                      return false;
                    }
                    """
                )
                if js_ok:
                    clicked = True

    # Also press Enter as standard form submission fallback
    with suppress(Exception):
        await page.keyboard.press("Enter")
        clicked = True

    if clicked:
        logger.success("Submitted Epic authenticator 2FA code")
        await page.wait_for_timeout(2000)

    return clicked
