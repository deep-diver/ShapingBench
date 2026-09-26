#!/usr/bin/env python3
"""Extract replayable URL/IRI contracts from curl/libcurl URL API releases."""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".replay" / "url_iri" / "curl-repo"
CHANGES = ROOT / ".replay" / "url_iri" / "curl-meta" / "changes.html"
RUNNER = ROOT / ".replay" / "url_iri" / "curl_urlapi_runner"
OUT_DIR = ROOT / "contracts" / "url_iri" / "curl"
OUT_JSON = OUT_DIR / "all_releases_maximal_language_independent.summary.json"
OUT_RPL = OUT_DIR / "all_releases_maximal_language_independent.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"

CURLU_DEFAULT_PORT = 1 << 0
CURLU_NO_DEFAULT_PORT = 1 << 1
CURLU_DEFAULT_SCHEME = 1 << 2
CURLU_NON_SUPPORT_SCHEME = 1 << 3
CURLU_PATH_AS_IS = 1 << 4
CURLU_DISALLOW_USER = 1 << 5
CURLU_URLDECODE = 1 << 6
CURLU_URLENCODE = 1 << 7
CURLU_APPENDQUERY = 1 << 8
CURLU_GUESS_SCHEME = 1 << 9
CURLU_NO_AUTHORITY = 1 << 10
CURLU_ALLOW_SPACE = 1 << 11
CURLU_PUNYCODE = 1 << 12
CURLU_PUNY2IDN = 1 << 13
CURLU_GET_EMPTY = 1 << 14
CURLU_NO_GUESS_SCHEME = 1 << 15


@dataclass(frozen=True)
class Seed:
    version: str
    name: str
    capability: str
    op: str
    args: list[str]
    evidence: str
    source: str


def version_key(tag: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"curl-(\d+)_(\d+)_(\d+)", tag)
    if not match:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:54] or "empty"


def sh(cmd: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd or ROOT, text=True).strip()


def release_rows() -> list[dict[str, Any]]:
    tags = sh(["git", "-C", str(REPO), "tag", "--list", "curl-*"]).splitlines()
    names = sorted({tag for tag in tags if re.fullmatch(r"curl-\d+_\d+_\d+", tag)}, key=version_key)
    return [
        {
            "version": ".".join(str(part) for part in version_key(name)),
            "tag": name,
            "has_urlapi_surface": version_key(name) >= (7, 62, 0),
        }
        for name in names
    ]


def change_items() -> list[str]:
    text = CHANGES.read_text(encoding="utf-8", errors="ignore")
    raw = re.findall(r"<li>\s*(?:<a [^>]+>)?([^<\n]+)(?:</a>)?", text)
    out = []
    for item in raw:
        item = (
            item.replace("&quot;", '"')
            .replace("&apos;", "'")
            .replace("&amp;", "&")
            .strip()
        )
        if "urlapi:" in item.lower() or "curl_url_" in item:
            out.append(item)
    return out


def run(seed: Seed) -> dict[str, Any]:
    raw = subprocess.check_output([str(RUNNER), seed.op, *seed.args], cwd=ROOT, text=True)
    return json.loads(raw)


def add(out: list[Seed], version: str, name: str, capability: str, op: str, args: list[Any], phrase: str, source: str) -> None:
    out.append(
        Seed(
            version=version,
            name=f"{version}:{name}",
            capability=capability,
            op=op,
            args=[str(arg) for arg in args],
            evidence=f"curl/libcurl {version}: {phrase}",
            source=source,
        )
    )


def seeds() -> list[Seed]:
    out: list[Seed] = []

    parse_inputs = [
        ("7.62.0", "full_components_https", "https://user:pass@example.com:443/a/b?x=1#frag", 0, 0, "URL API parses full hierarchical URLs into externally visible components."),
        ("7.62.0", "path_dedotdot", "https://example.com/a/b/../c/./d", 0, 0, "URL get returns a cleaned full URL unless path-as-is is requested."),
        ("7.62.0", "path_as_is", "https://example.com/a/b/../c/./d", CURLU_PATH_AS_IS, 0, "CURLU_PATH_AS_IS preserves dot-segments during URL parsing."),
        ("7.62.0", "default_https_scheme", "example.com/path", CURLU_DEFAULT_SCHEME, 0, "CURLU_DEFAULT_SCHEME accepts scheme-less host input as HTTPS."),
        ("7.62.0", "guess_ftp_scheme", "ftp.example.com/path", CURLU_GUESS_SCHEME, 0, "CURLU_GUESS_SCHEME guesses scheme from known host prefixes."),
        ("7.62.0", "guess_http_scheme", "example.com/path", CURLU_GUESS_SCHEME, 0, "CURLU_GUESS_SCHEME uses HTTP when no protocol-like host prefix applies."),
        ("8.9.0", "guess_http_no_guess_get", "example.com/path", CURLU_GUESS_SCHEME, CURLU_NO_GUESS_SCHEME, "CURLU_NO_GUESS_SCHEME hides a scheme that came from guessing."),
        ("7.62.0", "no_scheme_error", "example.com/path", 0, 0, "Parsing a URL without a scheme fails without default or guessing flags."),
        ("7.62.0", "unsupported_scheme_error", "madeup://example.com/path", 0, 0, "Unknown schemes fail by default."),
        ("7.62.0", "unsupported_scheme_allowed", "madeup://example.com/path", CURLU_NON_SUPPORT_SCHEME, 0, "CURLU_NON_SUPPORT_SCHEME accepts unknown hierarchical schemes."),
        ("7.62.0", "credentials_allowed", "https://user:pass@example.com/", 0, 0, "Embedded userinfo is parsed by default."),
        ("7.62.0", "credentials_disallowed", "https://user:pass@example.com/", CURLU_DISALLOW_USER, 0, "CURLU_DISALLOW_USER rejects URLs with embedded credentials."),
        ("7.67.0", "no_authority_custom_scheme", "foo:///path-only", CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY, 0, "CURLU_NO_AUTHORITY allows a custom scheme with empty authority."),
        ("7.78.0", "space_disallowed", "https://example.com/a b", 0, 0, "Spaces are rejected unless CURLU_ALLOW_SPACE is set."),
        ("7.78.0", "space_allowed", "https://example.com/a b", CURLU_ALLOW_SPACE, 0, "CURLU_ALLOW_SPACE accepts URL spaces where possible."),
        ("7.78.0", "space_allowed_encoded", "https://example.com/a b", CURLU_ALLOW_SPACE | CURLU_URLENCODE, 0, "CURLU_URLENCODE stores allowed URL spaces encoded."),
        ("7.62.0", "default_port_http", "http://example.com/path", 0, CURLU_DEFAULT_PORT, "CURLU_DEFAULT_PORT returns the scheme default when no port is stored."),
        ("7.62.0", "no_default_port_http_80", "http://example.com:80/path", 0, CURLU_NO_DEFAULT_PORT, "CURLU_NO_DEFAULT_PORT suppresses a stored default port."),
        ("7.62.0", "default_port_https", "https://example.com/path", 0, CURLU_DEFAULT_PORT, "Default port extraction is scheme-sensitive."),
        ("7.62.0", "port_65535", "https://example.com:65535/path", 0, 0, "Maximum valid TCP port is accepted."),
        ("7.62.0", "port_65536_error", "https://example.com:65536/path", 0, 0, "Ports above 65535 are rejected."),
        ("8.8.0", "port_zero", "https://example.com:0/path", 0, 0, "Port number zero is accepted by the URL API."),
        ("7.81.0", "ipv6_shortened", "http://[2001:0db8:0000:0000:0000:0000:0000:0001]/", 0, 0, "Numeric IPv6 hosts are normalized to their shortest bracketed form."),
        ("7.65.0", "ipv6_zoneid", "http://[fe80::1%25eth0]/path", 0, 0, "IPv6 zone identifiers are exposed separately from host."),
        ("7.62.0", "invalid_ipv6", "http://[2001:db8:::1]/", 0, 0, "Malformed IPv6 literals are rejected."),
        ("7.81.0", "short_file_url_rejected", "file://", 0, 0, "Short malformed file URLs are rejected."),
        ("8.20.0", "file_root_handling", "file:///", 0, 0, "The URL API has explicit handling for file root URLs."),
        ("8.21.0", "file_localhost_path", "file://localhost/tmp/a", 0, 0, "File URL host/path parsing is observable through the URL API."),
        ("8.21.0", "forbid_pipe_in_host", "https://exa|mple.com/", 0, 0, "Hostnames containing a vertical bar are rejected."),
        ("7.87.0", "forbid_percent_in_host", "https://exa%mple.com/", 0, 0, "Raw percent bytes are illegal in hostnames."),
        ("8.21.0", "deny_double_trailing_dot", "https://example.com../", 0, 0, "Hostnames with more than one trailing dot are rejected."),
        ("8.21.0", "consume_ipv4_trailing_dot", "http://127.0.0.1./", 0, 0, "A trailing dot after a numerical IPv4 address is consumed."),
        ("8.21.0", "accept_0x_ipv4", "http://0X7f.0.0.1/", 0, 0, "IPv4 numerical parsing accepts a 0X prefix."),
        ("8.21.0", "decode_hostname_before_ip_normalization", "http://%31%32%37.0.0.1/", 0, 0, "Host percent-decoding occurs before IP address normalization."),
        ("8.9.0", "scheme_must_start_alpha", "1http://example.com/", 0, 0, "Schemes must start with an alphabetic character."),
        ("8.20.0", "scheme_last_letter_verified", "htt%70://example.com/", 0, 0, "Explicit schemes are validated through their final character."),
        ("8.8.0", "empty_query_default_absent", "https://example.com/path?", 0, 0, "Zero-length queries are absent by default."),
        ("8.8.0", "empty_query_get_empty", "https://example.com/path?", 0, CURLU_GET_EMPTY, "CURLU_GET_EMPTY exposes zero-length query parts and full URL delimiters."),
        ("8.8.0", "empty_fragment_default_absent", "https://example.com/path#", 0, 0, "Zero-length fragments are absent by default."),
        ("8.8.0", "empty_fragment_get_empty", "https://example.com/path#", 0, CURLU_GET_EMPTY, "CURLU_GET_EMPTY exposes zero-length fragment parts and full URL delimiters."),
    ]
    for version, name, url, set_flags, get_flags, phrase in parse_inputs:
        add(out, version, name, "curl.urlapi.parse", "parse", [url, set_flags, get_flags], phrase, "release-notes+public-urlapi-docs")

    part_gets = [
        ("7.62.0", "path_urldecode", "https://example.com/a%20b?q=a+b#frag%20x", "path", 0, CURLU_URLDECODE, "CURLU_URLDECODE decodes path percent escapes on get."),
        ("7.62.0", "query_urldecode_plus", "https://example.com/a%20b?q=a+b#frag%20x", "query", 0, CURLU_URLDECODE, "CURLU_URLDECODE decodes query plus signs to spaces."),
        ("7.62.0", "fragment_urldecode", "https://example.com/a%20b?q=a+b#frag%20x", "fragment", 0, CURLU_URLDECODE, "CURLU_URLDECODE decodes fragment percent escapes on get."),
        ("7.62.0", "scheme_not_urldecoded", "https://example.com/a", "scheme", 0, CURLU_URLDECODE, "Schemes are not URL-decoded on get."),
        ("7.62.0", "port_not_urldecoded", "https://example.com:443/a", "port", 0, CURLU_URLDECODE, "Ports are not URL-decoded on get."),
        ("7.88.0", "punycode_get_host", "https://faß.de/path", "host", 0, CURLU_PUNYCODE, "CURLU_PUNYCODE returns IDN hostnames as punycode when IDN is available."),
        ("7.88.0", "punycode_get_url", "https://faß.de/path", "url", 0, CURLU_PUNYCODE, "CURLU_PUNYCODE can normalize hostnames inside the full URL."),
        ("8.3.0", "puny2idn_get_host", "https://xn--fa-hia.de/path", "host", 0, CURLU_PUNY2IDN, "CURLU_PUNY2IDN converts punycode hosts to IDN UTF-8 when available."),
        ("8.3.0", "puny2idn_get_url", "https://xn--fa-hia.de/path", "url", 0, CURLU_PUNY2IDN, "CURLU_PUNY2IDN can convert punycode hostnames in a full URL."),
        ("7.62.0", "missing_user_code", "https://example.com/path", "user", 0, 0, "Missing userinfo returns a specific no-user URL API code."),
        ("7.62.0", "missing_password_code", "https://user@example.com/path", "password", 0, 0, "Missing password returns a specific no-password URL API code."),
        ("7.62.0", "missing_query_code", "https://example.com/path", "query", 0, 0, "Missing query returns a specific no-query URL API code."),
        ("7.62.0", "missing_fragment_code", "https://example.com/path", "fragment", 0, 0, "Missing fragment returns a specific no-fragment URL API code."),
        ("7.65.0", "missing_zoneid_code", "https://example.com/path", "zoneid", 0, 0, "Missing zone id returns a specific no-zoneid URL API code."),
    ]
    for version, name, url, part, set_flags, get_flags, phrase in part_gets:
        add(out, version, name, "curl.urlapi.get-parts", "getpart", [url, set_flags, part, get_flags], phrase, "release-notes+public-urlapi-docs")

    setters = [
        ("7.62.0", "set_scheme_https", "__EMPTY_HANDLE__", 0, "scheme", "https", 0, 0, "Individual scheme setting contributes to full URL generation."),
        ("7.62.0", "set_host_adds_authority", "__EMPTY_HANDLE__", 0, "host", "example.com", 0, 0, "Individual host setting contributes to authority serialization."),
        ("7.62.0", "set_path_prepends_slash", "https://example.com", 0, "path", "no-leading-slash", 0, 0, "Setting PATH prepends a slash if one is missing."),
        ("7.62.0", "set_path_urlencode", "https://example.com", 0, "path", "/a b/c+d", CURLU_URLENCODE, 0, "CURLU_URLENCODE encodes path bytes while preserving documented raw characters."),
        ("7.62.0", "set_query_plain", "https://example.com/path", 0, "query", "a=b c", 0, 0, "Setting QUERY stores URL-form bytes as supplied unless encoding is requested."),
        ("7.62.0", "set_query_urlencode_space_plus", "https://example.com/path", 0, "query", "a=b c", CURLU_URLENCODE, 0, "CURLU_URLENCODE converts spaces to pluses for query values."),
        ("7.62.0", "append_query_ampersand", "https://example.com/?shoes=2", 0, "query", "hat=1", CURLU_APPENDQUERY, 0, "CURLU_APPENDQUERY inserts an ampersand when appending to an existing query."),
        ("7.62.0", "append_query_encode_first_equal", "https://example.com/?shoes=2&hat=1", 0, "query", "candy=N&N", CURLU_APPENDQUERY | CURLU_URLENCODE, 0, "APPENDQUERY with URLENCODE skips the first equals sign and encodes data ampersands."),
        ("7.62.0", "set_fragment_plain", "https://example.com/path", 0, "fragment", "anchor one", 0, 0, "Fragment setters do not include the leading hash sign."),
        ("8.0.0", "set_fragment_urlencode_length", "https://example.com/path", 0, "fragment", "anchor one", CURLU_URLENCODE, 0, "Fragment URL encoding uses the right byte length."),
        ("7.62.0", "set_user_only_blank_password_shape", "https://example.com/path", 0, "user", "alice", 0, 0, "Setting only userinfo serializes a blank password shape."),
        ("7.62.0", "set_password_only_blank_user_shape", "https://example.com/path", 0, "password", "secret", 0, 0, "Setting only password serializes a blank username shape."),
        ("7.62.0", "set_options_independent", "https://user:pass@example.com/path", 0, "options", "auth=plain", 0, 0, "OPTIONS can be set independently on the URL object."),
        ("7.65.0", "set_zoneid_on_ipv6", "http://[fe80::1]/", 0, "zoneid", "eth0", 0, 0, "Zone ID can be set separately for numeric IPv6 hosts."),
        ("7.62.0", "set_port_zero", "https://example.com/path", 0, "port", "0", 0, 0, "Setting port zero is accepted."),
        ("7.62.0", "set_port_65535", "https://example.com/path", 0, "port", "65535", 0, 0, "Setting the maximum valid port succeeds."),
        ("7.62.0", "set_port_65536_fails", "https://example.com/path", 0, "port", "65536", 0, 0, "Setting an out-of-range port fails."),
        ("7.62.0", "set_bad_scheme_fails", "https://example.com/path", 0, "scheme", "1https", 0, 0, "Invalid explicitly set schemes fail."),
        ("7.62.0", "set_unknown_scheme_allowed_flag", "https://example.com/path", 0, "scheme", "custom", CURLU_NON_SUPPORT_SCHEME, 0, "Unknown schemes can be set when the non-supported-scheme flag is present."),
        ("7.62.0", "set_blank_host_fails", "https://example.com/path", 0, "host", "", 0, 0, "Blank host setting fails without no-authority semantics."),
        ("7.67.0", "set_blank_host_no_authority", "foo://example/path", CURLU_NON_SUPPORT_SCHEME, "host", "", CURLU_NO_AUTHORITY, 0, "CURLU_NO_AUTHORITY permits clearing host authority for custom URLs."),
        ("7.62.0", "clear_query", "https://example.com/path?a=b", 0, "query", "__NULL__", 0, 0, "Setting a part to NULL removes that URL component."),
        ("7.62.0", "clear_fragment", "https://example.com/path#frag", 0, "fragment", "__NULL__", 0, 0, "NULL fragment setting removes the fragment component."),
        ("7.62.0", "clear_all_by_null_url", "https://example.com/path?a=b#c", 0, "url", "__NULL__", 0, 0, "Setting CURLUPART_URL to NULL clears all URL parts."),
    ]
    for version, name, base, init_flags, part, value, set_flags, get_flags, phrase in setters:
        add(out, version, name, "curl.urlapi.set-parts", "setpart", [base, init_flags, part, value, set_flags, get_flags], phrase, "release-notes+public-urlapi-docs")

    scheme_validity = [
        ("bad!", "Scheme setter rejects illegal punctuation."),
        ("bad{", "Scheme setter rejects braces."),
        ("bad/", "Scheme setter rejects slash separators."),
        ("bad\\", "Scheme setter rejects backslash separators."),
        ("a!", "Scheme setter rejects exclamation marks."),
        ("a+123", "Scheme setter accepts plus after an initial alpha."),
        ("http-2", "Scheme setter accepts hyphen after an initial alpha."),
        ("http.1", "Scheme setter accepts dot after an initial alpha."),
        ("a+-.123", "Scheme setter accepts mixed plus, hyphen and dot after an initial alpha."),
        ("http-+++2", "Scheme setter accepts repeated plus/hyphen syntax after an initial alpha."),
        ("http.1--", "Scheme setter accepts trailing hyphen after an initial alpha."),
        ("+a123", "Scheme setter rejects leading plus."),
        ("-http2", "Scheme setter rejects leading hyphen."),
        (".http1", "Scheme setter rejects leading dot."),
        ("ABC2", "Scheme setter accepts uppercase alphabetic starts."),
        ("2CBA", "Scheme setter rejects leading digits."),
        ("", "Scheme setter rejects empty schemes."),
        ("a", "Scheme setter accepts one-letter schemes."),
        ("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd", "Scheme setter accepts forty-byte schemes."),
        ("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddde", "Scheme setter rejects schemes longer than forty bytes."),
    ]
    for value, phrase in scheme_validity:
        add(out, "8.20.0", f"scheme_validity_{slug(value)}", "curl.urlapi.scheme-validation", "setpart", ["__EMPTY_HANDLE__", 0, "scheme", value, CURLU_NON_SUPPORT_SCHEME, 0], phrase, "release-notes+public-tests")

    userinfo_options = [
        ("imap_options_split", "imap://foo:bar;abc@example.com/inbox", "options", 0, 0, "IMAP URLs parse semicolon user options separately from password."),
        ("smtp_options_split", "smtp://foo:bar;abc@example.com/", "options", 0, 0, "SMTP URLs parse semicolon user options separately from password."),
        ("pop3_options_split", "pop3://foo:bar;abc@example.com/", "options", 0, 0, "POP3 URLs parse semicolon user options separately from password."),
        ("http_semicolon_stays_password", "http://foo:bar;abc@example.com/", "password", 0, 0, "Non mail-like schemes keep semicolon content in the password component."),
        ("userinfo_disallow_bare", "https://foo:bar@example.com/", "url", CURLU_DISALLOW_USER, 0, "DISALLOW_USER rejects userinfo regardless of password/options shape."),
    ]
    for name, url, part, set_flags, get_flags, phrase in userinfo_options:
        add(out, "8.21.0", name, "curl.urlapi.userinfo-options", "getpart", [url, set_flags, part, get_flags], phrase, "release-notes+public-tests")

    ipv6_port_cases = [
        ("ipv6_no_port", "http://[fe80::250:56ff:fea7:da15]/", 0, 0, "Bracketed IPv6 without an explicit port reports no port."),
        ("ipv6_with_808", "http://[fe80::250:56ff;fea7:da15]:808/", 0, 0, "The public URL parser extracts a port after a bracketed IPv6-like host."),
        ("ipv6_zone_port_80", "http://[fe80::250:56ff:fea7:da15%25eth3]:80/", 0, 0, "Zone-id IPv6 URLs still expose the following port."),
        ("ipv6_port_81", "http://[fe80::250:56ff:fea7:da15]:81/", 0, 0, "Bracketed IPv6 with a numeric port exposes that port."),
        ("ipv6_bad_semicolon_port", "http://[fe80::250:56ff:fea7:da15];81/", 0, 0, "Malformed separators after a bracketed IPv6 host are rejected."),
        ("ipv6_bad_missing_colon_port", "http://[fe80::250:56ff:fea7:da15]80/", 0, 0, "A port after bracketed IPv6 must use a colon separator."),
        ("ipv6_empty_port", "http://[fe80::250:56ff:fea7:da15]:/", 0, 0, "An empty explicit port after bracketed IPv6 is observable."),
        ("ipv6_raw_zone_port", "http://[fe80::250:56ff:fea7:da15%eth3]:80/", 0, 0, "Non percent-encoded zone indexes are accepted by the URL parser."),
    ]
    for name, url, set_flags, get_flags, phrase in ipv6_port_cases:
        add(out, "8.21.0", name, "curl.urlapi.ipv6-port", "parse", [url, set_flags, get_flags], phrase, "release-notes+public-tests")

    relatives = [
        ("7.62.0", "relative_parent_path", "https://example.com/a/b/c?old=1#frag", 0, "../d?new=1", 0, 0, "Setting a relative URL redirects against the existing URL."),
        ("7.62.0", "relative_absolute_path", "https://example.com/a/b/c", 0, "/root", 0, 0, "Root-relative redirects preserve scheme and authority."),
        ("8.8.0", "relative_fragment_only", "https://example.com/a/b?x=1#old", 0, "#new", 0, 0, "Fragment-only relative redirects update only the fragment."),
        ("8.8.0", "relative_query_only", "https://example.com/a/b?x=1#old", 0, "?y=2", 0, 0, "Query-only relative redirects update query while following URL semantics."),
        ("8.5.0", "relative_empty_redirect", "https://example.com/a/b?x=1#old", 0, "", 0, 0, "A blank URL is accepted as a redirect when a base URL already exists."),
        ("8.21.0", "relative_empty_redirect_drops_fragment", "https://example.com/a/b?x=1#old", 0, "", 0, CURLU_GET_EMPTY, "Empty redirect handling drops the base fragment consistently."),
        ("8.20.0", "relative_leading_dot", "https://example.com/a/b/c", 0, "./../d", 0, 0, "Relative dedotdotify handles leading dot segments correctly."),
        ("8.7.0", "relative_percent_dot_sequences", "https://example.com/a/b/c", 0, "%2e%2e/d", 0, 0, "Percent-encoded dot sequences are removed from URL paths where applicable."),
        ("8.21.0", "relative_no_guess_default_scheme", "example.com/a/b", CURLU_DEFAULT_SCHEME, "../c", 0, 0, "Redirects without an explicit set scheme work with default-scheme handling."),
        ("8.9.0", "relative_no_guess_get_flag", "example.com/a/b", CURLU_GUESS_SCHEME, "../c", 0, CURLU_NO_GUESS_SCHEME, "Redirect handling respects CURLU_NO_GUESS_SCHEME on later get."),
    ]
    for version, name, base, base_flags, rel, rel_flags, get_flags, phrase in relatives:
        add(out, version, name, "curl.urlapi.relative", "relative", [base, base_flags, rel, rel_flags, get_flags], phrase, "release-notes+public-urlapi-docs")

    duplicates = [
        ("7.62.0", "dup_path_independent", "https://example.com/a/b?x=1#f", 0, "path", "/changed", 0, 0, "curl_url_dup returns an independent URL handle copy."),
        ("7.65.0", "dup_zoneid_independent", "http://[fe80::1%25eth0]/", 0, "zoneid", "en1", 0, 0, "Duplicated handles retain and independently mutate zone IDs."),
        ("7.62.0", "dup_query_independent", "https://example.com/a?x=1", 0, "query", "y=2", 0, 0, "Mutating a duplicate query leaves the original URL unchanged."),
        ("7.62.0", "dup_fragment_independent", "https://example.com/a#old", 0, "fragment", "new", 0, 0, "Mutating a duplicate fragment leaves the original URL unchanged."),
    ]
    for version, name, base, base_flags, part, value, set_flags, get_flags, phrase in duplicates:
        add(out, version, name, "curl.urlapi.duplication", "dup", [base, base_flags, part, value, set_flags, get_flags], phrase, "release-notes+public-urlapi-docs")

    for code in range(0, 32):
        add(out, "7.81.0", f"strerror_code_{code}", "curl.urlapi.error-reporting", "strerror", [code], "curl_url_strerror exposes stable human-readable diagnostics for URL API codes.", "release-notes+public-urlapi-docs")
    add(out, "8.1.0", "cleanup_null_noop", "curl.urlapi.lifecycle", "cleanup_null", [], "curl_url_cleanup(NULL) is documented as a safe no-op.", "release-notes+public-urlapi-docs")

    return out


def contract_to_rpl(contract: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"contract {contract['name']} {{",
            f"  version = {json.dumps(contract['version'])}",
            f"  capability = {json.dumps(contract['capability'])}",
            f"  op = {json.dumps(contract['op'])}",
            f"  args = {json.dumps(contract['args'], ensure_ascii=False)}",
            f"  expect = {json.dumps(contract['expected'], ensure_ascii=False, sort_keys=True)}",
            f"  mutant = {json.dumps(contract['mutant'])}",
            "}",
        ]
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = release_rows()
    items = change_items()
    contracts = []
    failures = []
    for seed in seeds():
        try:
            expected = run(seed)
        except subprocess.CalledProcessError as exc:
            failures.append({"name": seed.name, "op": seed.op, "args": seed.args, "error": str(exc)})
            continue
        contracts.append(
            {
                "name": seed.name,
                "version": seed.version,
                "capability": seed.capability,
                "op": seed.op,
                "args": seed.args,
                "expected": expected,
                "evidence": seed.evidence,
                "source": seed.source,
                "mutant": "mutate_expected_observation",
            }
        )

    by_release = Counter(contract["version"] for contract in contracts)
    by_capability = Counter(contract["capability"] for contract in contracts)
    by_op = Counter(contract["op"] for contract in contracts)
    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "curl/curl",
                "package": "libcurl URL API",
                "latest_version": "8.21.0",
                "release_tags_inspected": len(rows),
                "release_note_urlapi_items": len(items),
                "release_rows": rows,
                "source_urlapi_items": items,
                "extraction_failures": failures,
                "contracts": contracts,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_RPL.write_text("\n\n".join(contract_to_rpl(contract) for contract in contracts) + "\n", encoding="utf-8")

    counts = [
        "# curl URL API Release Contract Counts",
        "",
        "| Release | Extracted contracts | URL API surface present |",
        "| --- | ---: | --- |",
    ]
    for row in rows:
        counts.append(f"| `{row['version']}` | {by_release.get(row['version'], 0)} | {row['has_urlapi_surface']} |")
    OUT_COUNTS.write_text("\n".join(counts) + "\n", encoding="utf-8")

    audit = [
        "# curl URL API Extraction Audit",
        "",
        f"- Git tags inspected: `{len(rows)}`",
        f"- `urlapi` / `curl_url_*` changelog items inspected: `{len(items)}`",
        f"- Extracted contracts: `{len(contracts)}`",
        f"- Extraction failures: `{len(failures)}`",
        "",
        "## By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for capability, count in by_capability.most_common():
        audit.append(f"| `{capability}` | {count} |")
    audit.extend(["", "## By Operation", "", "| Operation | Count |", "| --- | ---: |"])
    for op, count in by_op.most_common():
        audit.append(f"| `{op}` | {count} |")
    OUT_AUDIT.write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps({"release_tags_inspected": len(rows), "urlapi_items": len(items), "extracted_contracts": len(contracts), "extraction_failures": len(failures)}, sort_keys=True))


if __name__ == "__main__":
    main()
