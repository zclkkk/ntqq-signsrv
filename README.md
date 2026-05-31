# ntqq-signsrv

PC SignAPI server for acidify (NTQQ protocol implementation).

Loads QQ's `wrapper.node` and exposes the signing function via HTTP, compatible with acidify's `UrlSignProvider`.

## Quick Start

### 1. Download release

Get `ntqq-signsrv-linux-x64.tar.gz` from [Releases](../../releases).

```bash
tar xzf ntqq-signsrv-linux-x64.tar.gz
cd ntqq-signsrv-linux-x64
```

### 2. Extract QQ files

```bash
# From .deb package
mkdir -p runtime/app
dpkg-deb -x /path/to/linuxqq_*.deb /tmp/qq-extract
cp -r /tmp/qq-extract/opt/QQ/resources/app/* runtime/app/
```

### 3. Run

```bash
./ntqq-signsrv
```

The server auto-detects the QQ version from `runtime/app/package.json` and loads the corresponding version data.

## Configuration

`config.toml`:

```toml
[server]
host = "127.0.0.1"
port = 8080
```

## API

### POST /

Sign a packet. Matches acidify `UrlSignProvider` format.

```bash
curl -X POST http://127.0.0.1:8080/ \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"wtlogin.login","src":"01020304","seq":1}'
```

Response:

```json
{
  "platform": "Linux",
  "version": "3.2.27-47354",
  "value": {
    "sign": "hex...",
    "token": "hex...",
    "extra": "hex..."
  }
}
```

### GET /appinfo

Returns AppInfo JSON for acidify initialization.

```bash
curl http://127.0.0.1:8080/appinfo
```

## Yogurt Integration

In Yogurt's `config.json`:

```json
{
  "configVersion": 3,
  "protocol": {
    "os": "Linux",
    "version": "fetched",
    "signApiUrl": "http://127.0.0.1:8080"
  }
}
```

Set `version` to `"fetched"` so Yogurt fetches AppInfo from this server.

## Supported Versions

Version data is in `versions/`. Add new QQ versions by creating a JSON file with `sign_offset` (extracted from `wrapper.node`) and `appinfo` fields.

## Architecture

```
Yogurt  ──GET /appinfo──>  ntqq-signsrv  ──>  versions/*.json
   │                           │
   └──POST / {cmd,src,seq}──>  ├── dlopen(wrapper.node)
                               └── call sign() at offset
                                   └──> {sign, token, extra}
```
