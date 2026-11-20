# base Submodule Guide

## Scope

`base` provides the cross-platform C/C++ implementation behind the JsppRTC client.
It is built as the `rtcbase` CMake module and is consumed by the iOS and Android
wrappers in the parent repository.

## Source layout

- Core signalling, HTTP, certificate, JSON, STUN, and WebSocket code lives at
  the module root.
- Design notes in Chinese live under `docs/` (e.g. `docs/clock-offset-store.md`
  for nodelist `clockOffset` persistence).
- `quic/` contains the QUIC transport implementation. Keep its public headers
  in `quic/include/quic/` and implementation files in `quic/src/`.
- `libev/` and `protobuf-c/` are vendored C dependencies. Avoid unrelated
  formatting or behavioural changes in them.
- Generated protobuf sources are `rtc.pb-c.c` and `rtc.pb-c.h`; update them
  from their schema/generator rather than hand-editing them when possible.

## Build and validation

- Use CMake 3.16 or newer. The module requires C++23 and builds with hidden
  symbol visibility, thin LTO, and `JSON_NOEXCEPTION`.
- Configure the target platform explicitly. Platform dependencies are supplied
  by the parent repository under `libs/`:
  - iOS uses XCFrameworks for curl, OpenSSL, and ngtcp2.
  - Android uses the corresponding ABI-specific libraries.
- Keep generated build directories such as `build/` out of version control.
- After modifying build configuration or native code, at minimum configure and
  build the affected platform. Exercise the relevant signalling or transport
  path when changing protocol-facing code.

## Change conventions

- Preserve the existing public C++ and Objective-C++ interfaces unless a
  breaking change is explicitly intended.
- Prefer focused changes; do not mix dependency vendoring, generated-file
  churn, or broad reformatting with functional work.
- Maintain the existing C++ style and keep platform-specific code behind its
  `IOS` or `ANDROID` CMake guard.
- Treat URL, certificate, signalling token, and WebSocket/QUIC data as
  untrusted input. Validate errors and propagate failures through the existing
  callback/error paths.
