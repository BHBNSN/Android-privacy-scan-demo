import json
from collections import deque
from typing import Any
import argparse
import os

import requests

url = "http://localhost:8651"


def _log(msg: str) -> None:
    print(msg, flush=True)


def _safe_get_json(resp: requests.Response) -> dict:
    try:
        return resp.json() or {}
    except Exception:
        return {}


def _get_manifest(instance_id: str, base_url: str = url) -> str:
    data = _safe_get_json(
        requests.get(
            f"{base_url}/get_manifest",
            params={"instanceId": instance_id},
            timeout=60,
        )
    )
    return str(data.get("result") or "")


def _extract_package_and_company(manifest_xml: str) -> tuple[str, str]:
    """Best-effort parse package="..." from AndroidManifest.xml content string."""
    if not manifest_xml:
        return "", ""
    try:
        package = manifest_xml.split("package=")[1].split("\n")[0].replace('"', "").strip()
    except Exception:
        return "", ""

    parts = [p for p in package.split(".") if p]
    if len(parts) >= 2:
        return package, f"{parts[0]}.{parts[1]}"
    return package, package


def get_method_callers(
    instance_id: str,
    method_signature: str,
    base_url: str = url,
    *,
    timeout_s: int = 60,
) -> list[str]:
    """Return callers (method signatures) of the given method."""
    data = _safe_get_json(
        requests.get(
            f"{base_url}/get_method_callers",
            params={
                "instanceId": instance_id,
                "methodName": method_signature,
            },
            timeout=timeout_s,
        )
    )
    result = data.get("result")
    if not isinstance(result, list):
        return []
    return [str(m) for m in result if str(m).strip()]


def search_methods_by_strings(
    *,
    search_string_list: list[str],
    instance_id: str,
    base_url: str = url,
    company_prefix: str | None = None,
    timeout_s: int = 120,
) -> dict[str, list[str]]:
    """Search methods containing any of the given strings.

    Returns: {method_signature: [matched_search_string, ...]}
    """
    data = _safe_get_json(
        requests.get(
            f"{base_url}/search_strings_from_all_classes",
            params={
                "instanceId": instance_id,
                "searchStrings": json.dumps(search_string_list, ensure_ascii=False),
            },
            timeout=timeout_s,
        )
    )
    response_methods = data.get("result")
    if not isinstance(response_methods, dict):
        return {}

    result: dict[str, list[str]] = {}
    for method, strings in response_methods.items():
        method_sig = str(method)
        if company_prefix and not method_sig.startswith(company_prefix):
            continue
        if isinstance(strings, list):
            result[method_sig] = [str(s) for s in strings if str(s).strip()]
        else:
            result[method_sig] = [str(strings)] if strings is not None else []
    return result


def _build_call_graph_from_sinks(
    *,
    instance_id: str,
    sink_methods: list[str],
    base_url: str,
    max_depth: int,
    max_callers_per_method: int,
    max_total_methods: int,
) -> dict[str, Any]:
    """Upward call graph from sinks using get_method_callers.

    Edges are caller -> callee.
    """
    callers_cache: dict[str, list[str]] = {}
    callers_map: dict[str, list[str]] = {}
    edges: list[dict[str, str]] = []

    limits_hit = {
        "max_depth_hit": False,
        "max_total_methods_hit": False,
        "callers_truncated_methods": 0,
        "paths_truncated": False,
    }

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    for m in sink_methods:
        if m and m not in visited:
            visited.add(m)
            queue.append((m, 0))

    while queue:
        method_sig, depth = queue.popleft()
        if len(visited) >= max_total_methods:
            limits_hit["max_total_methods_hit"] = True
            break
        if depth >= max_depth:
            limits_hit["max_depth_hit"] = True
            continue

        if method_sig in callers_cache:
            callers = callers_cache[method_sig]
        else:
            callers = get_method_callers(instance_id, method_sig, base_url=base_url)
            _log("[get_method_callers] {} -> {} callers".format(method_sig, len(callers)))
            callers_cache[method_sig] = callers

        if max_callers_per_method > 0 and len(callers) > max_callers_per_method:
            callers = callers[:max_callers_per_method]
            limits_hit["callers_truncated_methods"] += 1

        callers_map[method_sig] = callers
        for caller in callers:
            edges.append({"caller": caller, "callee": method_sig})
            if caller not in visited:
                visited.add(caller)
                queue.append((caller, depth + 1))

    # roots: nodes with no callers (or callers_map missing/empty)
    nodes = set(visited)
    roots = []
    for n in nodes:
        cs = callers_map.get(n)
        if cs is None or len(cs) == 0:
            roots.append(n)

    return {
        "nodes": sorted(nodes),
        "sinks": list(sink_methods),
        "roots": sorted(roots),
        "edges": edges,
        "callers_map": callers_map,
        "limits": {
            "max_depth": max_depth,
            "max_callers_per_method": max_callers_per_method,
            "max_total_methods": max_total_methods,
            **limits_hit,
        },
    }


def _enumerate_paths_to_roots(
    *,
    sink: str,
    callers_map: dict[str, list[str]],
    max_depth: int,
    max_paths: int,
) -> tuple[list[list[str]], bool]:
    """Enumerate example paths root->...->sink by walking callers_map backwards."""
    paths: list[list[str]] = []
    truncated = False

    # path is stored as sink->...->currentCaller, then reversed
    stack: list[tuple[str, list[str], int]] = [(sink, [sink], 0)]
    while stack:
        node, rev_path, depth = stack.pop()
        if len(paths) >= max_paths:
            truncated = True
            break
        if depth >= max_depth:
            # reached depth cap; treat current as root-ish
            paths.append(list(reversed(rev_path)))
            continue

        callers = callers_map.get(node) or []
        if not callers:
            paths.append(list(reversed(rev_path)))
            continue

        for caller in callers:
            if caller in rev_path:
                continue
            stack.append((caller, rev_path + [caller], depth + 1))

    return paths, truncated


def collect_permission_methods(
    apk_path: str,
    permission_search_map: dict[str, list[str]],
    base_url: str = url,
    *,
    instance_id: str | None = None,
    recursion_limits: dict[str, int] | None = None,
    restrict_to_company: bool = True,
    verbose: bool = True,
):
    """Collect per-permission API hits + upward call chains (roots->...->sink).

    说明：
    - sink = 命中敏感接口字符串的 method（直接使用接口的地方）
    - root = 0 调用者（或在可获取范围内没有 callers 的顶层）
    - 调用链是“预提取”，可能因匿名类/反射/动态代理等不完整

    Returns:
      {
        "instanceId": str,
        "package": str,
        "company": str,
        "by_permission": {
           permission: {
             "hits": { method: {"matched_strings": [...] } },
             "call_graph": {roots/sinks/edges/callers_map/limits/nodes},
             "roots_index": { root_method: {"sinks": [...], "paths": [[...]], "sink_hits": {...}}}
           }
        }
      }
    """
    limits = recursion_limits or {}
    max_depth = int(limits.get("max_depth") or 5)
    max_callers_per_method = int(limits.get("max_callers_per_method") or 30)
    max_total_methods = int(limits.get("max_total_methods") or 800)

    if not instance_id:
        if verbose:
            _log(f"[get_permisson_methods] load APK -> instanceId: {apk_path}")
        resp = requests.get(
            f"{base_url}/load",
            params={"filePath": apk_path},
            timeout=120,
        )
        data = _safe_get_json(resp)
        instance_id = str(data.get("result") or "").strip()
        if not instance_id:
            raise RuntimeError(f"load() 未返回有效 instanceId: {data}")

    if verbose:
        _log(f"[get_permisson_methods] instanceId={instance_id}")

    manifest = _get_manifest(instance_id, base_url=base_url)
    package, company = _extract_package_and_company(manifest)
    company_prefix = company if (restrict_to_company and company) else None

    if verbose:
        _log(f"[get_permisson_methods] package={package} company={company_prefix or ''}")

    # 1) 全量搜索：method -> matched strings
    all_search_strings: list[str] = []
    for _perm, search_strings in (permission_search_map or {}).items():
        if isinstance(search_strings, list):
            all_search_strings.extend([str(s) for s in search_strings if str(s).strip()])

    all_search_strings = sorted(set(all_search_strings))
    if verbose:
        _log(f"[get_permisson_methods] search_strings count={len(all_search_strings)}")
    method_hits_all = search_methods_by_strings(
        search_string_list=all_search_strings,
        instance_id=instance_id,
        base_url=base_url,
        company_prefix=company_prefix,
    )

    if verbose:
        _log(f"[get_permisson_methods] hit_methods={len(method_hits_all)}")

    # 2) 归类到每个 permission：只保留属于该 permission 的 search_strings
    by_permission: dict[str, Any] = {}
    for permission, search_strings in (permission_search_map or {}).items():
        sset = set(str(s) for s in (search_strings or []) if str(s).strip())
        if not sset:
            by_permission[str(permission)] = {
                "hits": {},
                "call_graph": {
                    "nodes": [],
                    "sinks": [],
                    "roots": [],
                    "edges": [],
                    "callers_map": {},
                    "limits": {
                        "max_depth": max_depth,
                        "max_callers_per_method": max_callers_per_method,
                        "max_total_methods": max_total_methods,
                        "max_depth_hit": False,
                        "max_total_methods_hit": False,
                        "callers_truncated_methods": 0,
                        "paths_truncated": False,
                    },
                },
                "roots_index": {},
            }
            continue

        hits: dict[str, Any] = {}
        sinks: list[str] = []
        for method, matched in method_hits_all.items():
            mm = [m for m in (matched or []) if m in sset]
            if not mm:
                continue
            sinks.append(method)
            hits[method] = {"matched_strings": sorted(set(mm))}

        sinks = sorted(set(sinks))
        if verbose:
            _log(f"[get_permisson_methods] permission={permission} sinks={len(sinks)}")
        if not sinks:
            by_permission[str(permission)] = {
                "hits": {},
                "call_graph": {
                    "nodes": [],
                    "sinks": [],
                    "roots": [],
                    "edges": [],
                    "callers_map": {},
                    "limits": {
                        "max_depth": max_depth,
                        "max_callers_per_method": max_callers_per_method,
                        "max_total_methods": max_total_methods,
                        "max_depth_hit": False,
                        "max_total_methods_hit": False,
                        "callers_truncated_methods": 0,
                        "paths_truncated": False,
                    },
                },
                "roots_index": {},
            }
            continue

        call_graph = _build_call_graph_from_sinks(
            instance_id=instance_id,
            sink_methods=sinks,
            base_url=base_url,
            max_depth=max_depth,
            max_callers_per_method=max_callers_per_method,
            max_total_methods=max_total_methods,
        )

        # 3) 构建 roots_index：root_method -> {sinks/paths/sink_hits}
        roots_index: dict[str, Any] = {}
        callers_map: dict[str, list[str]] = call_graph.get("callers_map") or {}

        any_paths_truncated = False
        for sink in sinks:
            paths, truncated = _enumerate_paths_to_roots(
                sink=sink,
                callers_map=callers_map,
                max_depth=max_depth,
                max_paths=30,
            )
            if truncated:
                any_paths_truncated = True
            for path in paths:
                if not path:
                    continue
                root = path[0]
                roots_index.setdefault(root, {"sinks": [], "paths": [], "sink_hits": {}})
                if sink not in roots_index[root]["sinks"]:
                    roots_index[root]["sinks"].append(sink)
                # 控制每个 root 的 paths 数量
                if len(roots_index[root]["paths"]) < 50:
                    roots_index[root]["paths"].append(path)
                roots_index[root]["sink_hits"][sink] = hits.get(sink, {}).get("matched_strings", [])

        call_graph["limits"]["paths_truncated"] = bool(call_graph["limits"].get("paths_truncated")) or any_paths_truncated

        by_permission[str(permission)] = {
            "hits": hits,
            "call_graph": call_graph,
            "roots_index": roots_index,
        }

        if verbose:
            _log(
                f"[get_permisson_methods] permission={permission} roots={len(call_graph.get('roots') or [])} edges={len(call_graph.get('edges') or [])}"
            )

    return {
        "instanceId": instance_id,
        "package": package,
        "company": company,
        "by_permission": by_permission,
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract permission API hits and call chains")
    parser.add_argument("--apk", required=True, help="待分析 APK 路径")
    args = parser.parse_args()

    scan_manifest_path = "scan_manifest.json"
    jadx_daemon_url = "http://localhost:8651"
    permission_order = ["location", "clipboard"]

    with open(scan_manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    pws = manifest.get("permission_workflows") or {}
    if not isinstance(pws, dict) or not pws:
        raise SystemExit("scan_manifest.json 未配置 permission_workflows")

    instance_id: str | None = None
    combined: dict[str, Any] = {"by_permission": {}}

    for perm in permission_order:
        wf_path = pws.get(perm)
        if not wf_path:
            continue
        with open(wf_path, "r", encoding="utf-8") as f:
            wf = json.load(f)
        search_strings = wf.get("search_strings") or []
        if not isinstance(search_strings, list) or not search_strings:
            continue

        permission_search_map = {perm: [str(s) for s in search_strings if str(s).strip()]}
        out = collect_permission_methods(
            apk_path=args.apk,
            permission_search_map=permission_search_map,
            base_url=jadx_daemon_url,
            instance_id=instance_id,
        )
        instance_id = out.get("instanceId") or instance_id
        combined.setdefault("instanceId", instance_id)
        combined.setdefault("package", out.get("package"))
        combined.setdefault("company", out.get("company"))
        combined["by_permission"][perm] = (out.get("by_permission") or {}).get(perm) or {}

    print(json.dumps(combined, ensure_ascii=False, indent=2))