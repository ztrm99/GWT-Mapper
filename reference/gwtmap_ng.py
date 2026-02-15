#!/usr/bin/python3
"""
GWTMap NG v0.1
Modern GWT-RPC method enumerator for permutation cache.js files.
"""

import argparse
import re
import sys
import time
from getpass import getpass
from typing import Dict, List, Tuple

import requests
from requests.auth import HTTPBasicAuth

VERSION = "0.1"

F_SUFFIX = ".cache.js"
UNKNOWN = "UNKNOWN"

FORMAT = {
    "DEFAULT": "\033[0m",
    "HEADING": "\033[1m\033[1;34m",
    "ERROR": "\033[1m\033[31m",
    "WARNING": "\033[1m\033[1;33m",
}

COLOR_MODE = False

# HTTP settings
PROXIES = None
COOKIES = None
HTTP_AUTH = None

R_VAR = r"[A-Za-z0-9_\.$]+"

BANNER = r"""
   ____      ____  __  ___      _   __  ______
  / __ \____/ / / / / / / | /| / / / / / / __ \
 / / / / __  / / / / / /  |/ |/ / / /_/ / /_/ /
/ /_/ / /_/ / /_/ / / / /|  / / / __  / ____/
\____/\__,_/\____/ /_/_/ |_/_/ /_/ /_/_/
"""


def writer(text="", fmt=FORMAT["DEFAULT"]):
    if fmt == FORMAT["DEFAULT"] or not COLOR_MODE:
        print(text)
    else:
        print(rf"{fmt}{text}{FORMAT['DEFAULT']}")


def print_heading(text: str):
    writer(f"\n[+] {text}\n{'=' * 20}", FORMAT["HEADING"])


def classify_response(response: str) -> str:
    """Best-effort classify to decide on cleaning."""
    if response.startswith("function"):
        return "bootstrap_clean"
    if "onScriptDownloaded([" in response:
        return "permutation_obfuscated"
    return "unknown"


def retab(code: str) -> str:
    tabs, tabbed_code = 0, ""
    for line in code.split("\n"):
        if line.strip() == "}":
            tabs -= 1
        tabbed_code += tabs * "\t" + line + "\n"
        if line.strip().endswith("{"):
            tabs += 1
    return tabbed_code


def clean_code(code: str, code_type: str) -> List[str]:
    if code_type == "bootstrap_clean":
        return code.split("\n")

    # Obfuscated permutation or unknown
    code = code.replace("{", "{\\n").replace("}", "\\n}\\n").replace(";", ";\\n")
    try:
        code = retab(bytes(code, encoding="ascii").decode("unicode_escape"))
    except UnicodeDecodeError:
        # Fallback to raw if decode fails
        code = retab(code)
    return code.split("\n")


def set_http_params(args):
    global PROXIES, COOKIES, HTTP_AUTH
    requests.packages.urllib3.disable_warnings()

    if args.proxy is not None:
        PROXIES = {args.proxy.split(":")[0].lower(): args.proxy}

    if args.cookies is not None:
        cookies_list = {}
        for cookie in args.cookies.split(";"):
            if "=" not in cookie:
                continue
            key, val = cookie.split("=", 1)
            cookies_list[key.strip()] = val.strip()
        COOKIES = cookies_list

    if args.basic:
        print_heading("HTTP Basic Auth")
        username = input("Username: ")
        password = getpass("Password: ")
        HTTP_AUTH = HTTPBasicAuth(username, password)
        writer()


def http_request(url: str) -> Tuple[int, str]:
    try:
        response = requests.get(
            url, proxies=PROXIES, cookies=COOKIES, auth=HTTP_AUTH, verify=False
        )
        return response.status_code, response.text
    except requests.exceptions.RequestException as exc:
        writer(f"\nError: Connection failed for {url}: {exc}\n", FORMAT["ERROR"])
        sys.exit(1)


def fetch_code(url: str) -> Tuple[str, str]:
    status, response = http_request(url)
    if status != 200:
        writer(
            f"\nError: HTTP status {status} returned, 200 expected\n - {url}\n",
            FORMAT["ERROR"],
        )
        sys.exit(1)
    code_type = classify_response(response)
    return response, code_type


def read_file(file_path: str) -> Tuple[str, str]:
    try:
        with open(file_path, "r", errors="ignore") as file_obj:
            data = file_obj.read()
            return data, classify_response(data)
    except FileNotFoundError:
        writer(f"\nerror: Unable to read file {file_path}\n", FORMAT["ERROR"])
        sys.exit(1)


def write_file(data: str, file_path: str):
    try:
        with open(file_path, "w") as file_obj:
            file_obj.write(data)
    except OSError:
        writer(f"\nwarning: Unable to write backup file {file_path}\n", FORMAT["WARNING"])


def save_code(code: List[str], directory: str) -> str:
    output_code = "".join(code)
    out_name = f"{directory}/{str(int(time.time()))}{F_SUFFIX}"
    out_name = out_name.replace("//", "/")
    write_file(output_code, out_name)
    return out_name


def build_string_var_map(code: List[str]) -> Dict[str, str]:
    """Map obfuscated var -> string literal across the full buffer."""
    string_vars: Dict[str, str] = {}
    joined = "\n".join(code)
    for match in re.finditer(r"([A-Za-z0-9_\$]+)='([^']*)'", joined):
        string_vars[match.group(1)] = match.group(2)
    return string_vars


def resolve_string(value: str, string_vars: Dict[str, str]) -> str:
    if value in string_vars:
        return string_vars[value]
    return value


def detect_rpc_invoke_func(code: List[str], debug: bool) -> str:
    """Attempt multiple heuristics to find the obfuscated RPC invoke function."""
    fn_pattern = re.compile(r"^function ([A-Za-z0-9_\$]+)\(a,b,c\)\{")
    for i, line in enumerate(code):
        m = fn_pattern.match(line.strip())
        if not m:
            continue
        name = m.group(1)
        j_ub, h_ub = 0, 0
        for j in range(i + 1, min(i + 25, len(code))):
            if "JUb(" in code[j]:
                j_ub += 1
            if "HUb(" in code[j]:
                h_ub += 1
            if code[j].strip() == "}":
                break
        if j_ub >= 2 and h_ub >= 1:
            if debug:
                writer(f"[debug] invoke by JUb/HUb heuristic: {name}")
            return name

    # Fallback: count calls with literal interface names
    invoke_candidates: Dict[str, int] = {}
    literal_pattern = re.compile(r"\b([A-Za-z0-9_\$]+)\([^;]*'com\.[^']+'\s*,\s*\d+\s*\)")
    for line in code:
        lm = literal_pattern.search(line)
        if lm:
            invoke_candidates[lm.group(1)] = invoke_candidates.get(lm.group(1), 0) + 1

    if invoke_candidates:
        best = max(invoke_candidates, key=invoke_candidates.get)
        if debug:
            writer(f"[debug] invoke by literal-interface heuristic: {best}")
        return best

    if debug:
        writer("[debug] invoke function not detected")
    return ""


def extract_methods_modern(
    code: List[str],
    string_vars: Dict[str, str],
    debug: bool,
) -> List[Dict[str, str]]:
    """Extract methods using layered heuristics for modern GWT output."""
    invoke_fn = detect_rpc_invoke_func(code, debug)

    # Method constructor patterns
    new_pat_literal = re.compile(
        r"new\s+[A-Za-z0-9_\.$]+\([^;]*,\s*([A-Za-z0-9_\$]+)\s*,\s*'([^']+)'\s*\)"
    )
    new_pat_var = re.compile(
        r"new\s+[A-Za-z0-9_\.$]+\([^;]*,\s*([A-Za-z0-9_\$]+)\s*,\s*([A-Za-z0-9_\$]+)\s*\)"
    )

    # Invoke pattern(s)
    invoke_pat = None
    if invoke_fn:
        invoke_pat = re.compile(
            rf"\b{re.escape(invoke_fn)}\([^;]*,\s*([A-Za-z0-9_\$]+|'[^']+')\s*,\s*(\d+)\s*\)"
        )

    invoke_literal_pat = re.compile(
        r"\b([A-Za-z0-9_\$]+)\([^;]*'((?:com|org|net)\.[^']+)'\s*,\s*(\d+)\s*\)"
    )

    methods: List[Dict[str, str]] = []
    method_name_pattern = re.compile(r"^[A-Za-z0-9_\\$]+$")
    debug_hits = 0
    debug_misses = 0
    total_new = 0
    for i, line in enumerate(code):
        svc_var = None
        method_name = None
        origin = None

        m1 = new_pat_literal.search(line)
        if m1:
            total_new += 1
            svc_var, method_name = m1.group(1), m1.group(2)
            origin = "new_lit"
        else:
            m2 = new_pat_var.search(line)
            if m2:
                total_new += 1
                svc_var, method_name = m2.group(1), m2.group(2)
                resolved = resolve_string(method_name, string_vars)
                if resolved != method_name and resolved:
                    method_name = resolved
                    origin = "new_var"
                else:
                    continue

        if not svc_var or not method_name:
            continue
        if not method_name_pattern.match(method_name):
            continue

        iface_val = None
        param_count = None

        # scan forward
        for j in range(i, min(i + 30, len(code))):
            if invoke_pat:
                sm = invoke_pat.search(code[j])
                if sm:
                    iface_val = sm.group(1).strip("'")
                    param_count = sm.group(2)
                    break
            sm2 = invoke_literal_pat.search(code[j])
            if sm2:
                iface_val = sm2.group(2)
                param_count = sm2.group(3)
                break

        # scan backward if not found
        if iface_val is None:
            for j in range(max(0, i - 10), i):
                if invoke_pat:
                    sm = invoke_pat.search(code[j])
                    if sm:
                        iface_val = sm.group(1).strip("'")
                        param_count = sm.group(2)
                        break
                sm2 = invoke_literal_pat.search(code[j])
                if sm2:
                    iface_val = sm2.group(2)
                    param_count = sm2.group(3)
                    break

        if iface_val is None:
            if debug and debug_misses < 3:
                writer(f"[debug] no invoke for method={method_name} svc={svc_var}")
                debug_misses += 1
            continue

        iface_val = resolve_string(iface_val, string_vars)
        if not re.match(r"^(?:com|org|net)\.", iface_val):
            continue

        service_proxy = resolve_string(svc_var, string_vars)
        try:
            param_count_int = int(param_count) if param_count is not None else 0
        except ValueError:
            param_count_int = 0

        methods.append(
            {
                "serviceProxy": service_proxy,
                "rmtSvcIntName": iface_val,
                "methodName": method_name,
                "paramCount": str(param_count_int),
                "methodSignature": [UNKNOWN] * param_count_int,
                "origin": origin,
            }
        )
        if debug and debug_hits < 5:
            writer(
                f"[debug] add method={method_name} iface={iface_val} svc={service_proxy} count={param_count_int}"
            )
            debug_hits += 1

    if debug:
        writer(f"[debug] new() matches: {total_new}")
        writer(f"[debug] methods found (modern): {len(methods)}")

    return methods


def group_methods(methods: List[Dict[str, str]]) -> List[Tuple[str, List[Dict[str, str]]]]:
    groups: Dict[str, List[Dict[str, str]]] = {}
    for m in methods:
        label = m.get("serviceProxy") or m.get("rmtSvcIntName") or UNKNOWN
        if label.endswith("_Proxy"):
            label = label[:-6]
        elif label.endswith("Proxy"):
            label = label[:-5]
        if label == UNKNOWN:
            label = m.get("rmtSvcIntName", UNKNOWN)
        groups.setdefault(label, []).append(m)
    return sorted(groups.items(), key=lambda kv: kv[0])


def present_methods(methods: List[Dict[str, str]], quiet: bool, debug: bool):
    if not quiet:
        print_heading("Methods Found")
    if not methods:
        writer("No methods were identified!", FORMAT["WARNING"])
        return

    for label, items in group_methods(methods):
        writer(f"\n----- {label} -----\n")
        for m in items:
            sig = ", ".join(m.get("methodSignature", []))
            method_string = f"{label}.{m['methodName']}({(' ' + sig + ' ') if sig else ''})"
            method_string = method_string.replace("(  )", "()")
            writer(method_string)
            if debug:
                writer(
                    f"[debug] origin={m.get('origin')} iface={m.get('rmtSvcIntName')} count={m.get('paramCount')}"
                )


def present_services(methods: List[Dict[str, str]], quiet: bool):
    if not quiet:
        print_heading("Services Found")
    if not methods:
        writer("No services were identified!", FORMAT["WARNING"])
        return

    seen = set()
    for m in methods:
        iface = m.get("rmtSvcIntName")
        if iface and iface not in seen:
            seen.add(iface)
            writer(f"Interface: {iface}")
    writer()


def main():
    parser = argparse.ArgumentParser(description="Enumerates GWT-RPC methods from cache.js files")
    parser.add_argument("--version", action="version", version="%(prog)s {}".format(VERSION))
    parser.add_argument(
        "-u",
        "--url",
        metavar="<TARGET_URL>",
        required="-F" not in sys.argv and "--file" not in sys.argv,
        help="URL of the target {hex}.cache.js file",
    )
    parser.add_argument(
        "-F",
        "--file",
        metavar="<FILE>",
        nargs="+",
        default=None,
        required="-u" not in sys.argv and "--url" not in sys.argv,
        help="one or more local {hex}.cache.js files",
    )
    parser.add_argument(
        "-p",
        "--proxy",
        metavar="<PROXY>",
        default=None,
        help="URL for an optional HTTP proxy (e.g. -p http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "-c",
        "--cookies",
        metavar="<COOKIES>",
        default=None,
        help="cookies required to access the remote resource in -u/--url mode",
    )
    parser.add_argument(
        "--basic",
        action="store_true",
        default=False,
        help="enables HTTP Basic authentication if required",
    )
    parser.add_argument(
        "--svc",
        action="store_true",
        default=False,
        help="display enumerated service information, in addition to methods",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="prints debug info about detection heuristics",
    )
    parser.add_argument(
        "--backup",
        metavar="DIR",
        nargs="?",
        default=False,
        help="creates a local backup of retrieved code in -u/--url mode",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="enables quiet mode (minimal output)",
    )
    parser.add_argument(
        "--color",
        action="store_true",
        default=False,
        help="enables coloured console output",
    )

    args = parser.parse_args()

    global COLOR_MODE
    COLOR_MODE = args.color

    if not args.quiet:
        writer(BANNER, FORMAT["HEADING"])
        writer("".ljust(2) + f"version {VERSION}")

    set_http_params(args)

    targets: List[Tuple[str, str]] = []
    if args.file is not None:
        for path in args.file:
            targets.append(("file", path))
    else:
        targets.append(("url", args.url))

    for mode, target in targets:
        if not args.quiet:
            print_heading("Analysing")
            writer(target)

        if mode == "file":
            code, code_type = read_file(target)
        else:
            code, code_type = fetch_code(target)

        code_lines = clean_code(code, code_type)

        if args.backup is not False and mode == "url":
            backup_file = save_code(code_lines, args.backup)
            if args.debug:
                writer(f"[debug] backup saved: {backup_file}")

        string_vars = build_string_var_map(code_lines)
        if args.debug:
            writer(f"[debug] string vars: {len(string_vars)}")

        methods = extract_methods_modern(code_lines, string_vars, args.debug)

        if args.svc:
            present_services(methods, args.quiet)

        present_methods(methods, args.quiet, args.debug)


if __name__ == "__main__":
    main()
