import asyncio
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.mcp import MCPTools
from mcp import StdioServerParameters
import os
import argparse
import json
import re
from typing import Any

from collections import deque

from get_permisson_methods import collect_permission_methods


def _read_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _render_template(template: str, variables: dict[str, Any]) -> str:
    rendered = template
    for key, value in variables.items():
        rendered = rendered.replace(f"{{{key}}}", str(value))
    return rendered


def _extract_first_json_object(text: str) -> dict:
    """Best-effort: extract a JSON object from LLM output."""
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise ValueError("No JSON object found in init output")
    return json.loads(match.group(0))


def _build_scan_prompt(scan_manifest: dict, variables: dict[str, Any]) -> str:
    base = _render_template(scan_manifest["system_prompt"], variables)
    constraints = "\n".join(f"- {r}" for r in scan_manifest.get("rules", []))
    return (
        f"{base}\n\n"
        f"必须遵守以下规则：\n{constraints}\n\n"
        "【输出格式要求】\n"
        "- 必须输出严格 JSON（不要 Markdown 代码块）\n"
        "- JSON 必须包含字段：entry_point, is_wrapper_interface, confidence, evidence, callers\n"
    )


def _build_bootstrap_prompt(apk_path: str) -> str:
    return (
        "你需要通过 jadx MCP 初始化反编译上下文。\n"
        f"待分析的二进制文件路径是: `{apk_path}`。\n"
        "你必须调用 load(filePath) 加载该文件，并输出严格 JSON（不要 Markdown 代码块），格式为："
        '{"instanceId":"..."}'
    )


def _build_scenario_prompt(system_prompt: str, rules: list[str], variables: dict[str, Any]) -> str:
    base = _render_template(system_prompt, variables)
    constraints = "\n".join(f"- {r}" for r in rules or [])
    return (
        f"{base}\n\n"
        f"必须遵守以下规则：\n{constraints}\n\n"
        "【输出格式要求】\n"
        "- 必须输出严格 JSON（不要 Markdown 代码块）\n"
    )


def _get_recursion_limits(scan_manifest: dict) -> dict[str, int]:
    limits = scan_manifest.get("recursion_limits") or {}
    max_depth = int(limits.get("max_depth") or 5)
    max_callers_per_method = int(limits.get("max_callers_per_method") or 30)
    max_total_methods = int(limits.get("max_total_methods") or 800)
    return {
        "max_depth": max_depth,
        "max_callers_per_method": max_callers_per_method,
        "max_total_methods": max_total_methods,
    }


def _as_bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in {"true", "yes", "1"}:
            return True
        if value.lower() in {"false", "no", "0"}:
            return False
    return None

async def main():
    parser = argparse.ArgumentParser(description="Android wrapper check agent")
    parser.add_argument("--apk", required=True, help="待分析的 APK 路径")
    # 其余参数保持可选（不要求命令行提供），默认从环境变量读取
    parser.add_argument("--scan-manifest", default=os.getenv("SCAN_MANIFEST", "scan_manifest.json"))
    parser.add_argument("--workflow", default=os.getenv("PRISCAN_WORKFLOW", "priscan_workflow.json"))
    parser.add_argument(
        "--jadx-mcp-server",
        default=os.getenv("JADX_MCP_SERVER", "D:\\JAVAProjects\\jadx-daemon-mcp\\server.py"),
    )
    parser.add_argument("--jadx-host", default=os.getenv("JADX_DAEMON_MCP_HOST", "localhost"))
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "https://www.dmxapi.cn/v1"))
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", "GLM-4.5-Flash"))
    parser.add_argument(
        "--scenarios",
        default="D:\PyCharmProject\Android-privacy-scan\per.json",
        help="可选：外部输入的使用场景 JSON 文件路径（permission -> 场景列表）。提供后将执行场景符合性审计。",
    )
    args = parser.parse_args()

    # Define the MCP server configuration
    server_params = StdioServerParameters(
        command="python",
        args=[args.jadx_mcp_server],
        env={"JADX_DAEMON_MCP_HOST": args.jadx_host},
    )

    mcp_tools = MCPTools(
        transport="stdio",
        server_params=server_params
    )

    # Initialize the Agent with the MCP tools
    # IMPORTANT: never hard-code API keys in source code.
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("DMX_API_KEY")
    if not api_key:
        raise RuntimeError("未检测到 OPENAI_API_KEY（或 DMX_API_KEY）环境变量。")

    scan_manifest = _read_json_file(args.scan_manifest)
    permission_workflows = scan_manifest.get("permission_workflows") or {}
    permission_search_map = scan_manifest.get("permission_search_map") or {}

    per_permission_workflow: dict[str, dict[str, Any]] = {}
    per_permission_api_docs: dict[str, dict[str, Any]] = {}
    if isinstance(permission_workflows, dict) and permission_workflows:
        for permission, workflow_path in permission_workflows.items():
            if not workflow_path:
                continue
            wf = _read_json_file(str(workflow_path))
            per_permission_workflow[str(permission)] = wf
            api_docs = wf.get("api_docs")
            if isinstance(api_docs, dict):
                per_permission_api_docs[str(permission)] = api_docs
            else:
                per_permission_api_docs[str(permission)] = {}
        # 从 workflow 文件中提取搜索字符串
        derived_map: dict[str, list[str]] = {}
        for permission, wf in per_permission_workflow.items():
            search_strings = wf.get("search_strings")
            if isinstance(search_strings, list) and search_strings:
                derived_map[permission] = [str(s) for s in search_strings if str(s).strip()]
            else:
                derived_map[permission] = []
        permission_search_map = derived_map

    if not isinstance(permission_search_map, dict) or not permission_search_map:
        raise RuntimeError(
            "scan_manifest.json 未配置 permission_workflows 或 permission_search_map。\n"
            "推荐使用 permission_workflows: {permission: workflow_json_path}"
        )

    recursion_limits = _get_recursion_limits(scan_manifest)

    # Phase 0: 对每个权限用 get_permisson_methods 找到候选敏感调用点（method -> hit strings）
    permission_methods: dict[str, dict[str, list[str]]] = collect_permission_methods(
        apk_path=args.apk,
        permission_search_map=permission_search_map,
    )
    if not any(permission_methods.values()):
        print(json.dumps({}, ensure_ascii=False))
        return

    agent = Agent(
        model=OpenAIChat(
            id=args.model,
            base_url=args.base_url,
            api_key=api_key
        ),
        tools=[mcp_tools],
        markdown=True,
        debug_mode=True,
        system_message_role="user",
    )

    print("Starting agent with MCP tools...")
    async with mcp_tools:
        # We need to make sure tools are loaded before agent runs
        # The context manager calls connect() which calls initialize() which calls build_tools()
        # So mcp_tools.functions should be populated now.
        print(f"Tools available: {len(mcp_tools.functions)}")

        # Phase 1: bootstrap load once, reuse instanceId
        bootstrap_prompt = _build_bootstrap_prompt(args.apk)
        bootstrap_resp = await agent.arun(bootstrap_prompt)
        bootstrap_text = getattr(bootstrap_resp, "content", None) or str(bootstrap_resp)
        bootstrap_json = _extract_first_json_object(bootstrap_text)
        instance_id = str(bootstrap_json.get("instanceId") or "").strip()
        if not instance_id:
            raise RuntimeError("bootstrap 阶段未拿到有效 instanceId")

        # Phase 2: 递归上溯调用链，直到顶层非通用接口
        analysis_cache: dict[str, dict[str, Any]] = {}
        analyzed_count = 0

        async def analyze_method(method_sig: str) -> dict[str, Any]:
            nonlocal analyzed_count
            if method_sig in analysis_cache:
                return analysis_cache[method_sig]
            if analyzed_count >= recursion_limits["max_total_methods"]:
                result = {
                    "entry_point": method_sig,
                    "is_wrapper_interface": None,
                    "confidence": 0.0,
                    "evidence": [
                        f"达到分析上限 max_total_methods={recursion_limits['max_total_methods']}，停止继续分析",
                    ],
                    "callers": [],
                }
                analysis_cache[method_sig] = result
                return result

            scan_vars = {
                "input_file": args.apk,
                "priscan_workflow": args.workflow,
                "instanceId": instance_id,
                "entry_point": str(method_sig),
            }
            scan_prompt = _build_scan_prompt(scan_manifest, scan_vars)
            scan_resp = await agent.arun(scan_prompt)
            scan_text = getattr(scan_resp, "content", None) or str(scan_resp)

            parsed: dict[str, Any] = {
                "entry_point": method_sig,
                "is_wrapper_interface": None,
                "confidence": None,
                "evidence": ["模型输出无法解析为 JSON", scan_text[:5000]],
                "callers": [],
            }
            try:
                scan_json = _extract_first_json_object(scan_text)
                parsed["entry_point"] = scan_json.get("entry_point") or method_sig
                parsed["is_wrapper_interface"] = _as_bool_or_none(scan_json.get("is_wrapper_interface"))
                parsed["confidence"] = scan_json.get("confidence")
                parsed["evidence"] = scan_json.get("evidence") or []
                callers = scan_json.get("callers")
                if isinstance(callers, list):
                    parsed["callers"] = [str(c) for c in callers][: recursion_limits["max_callers_per_method"]]
            except Exception:
                pass

            analyzed_count += 1
            analysis_cache[method_sig] = parsed
            return parsed

        final_report: dict[str, Any] = {}

        for permission, methods_dict in permission_methods.items():
            # 每个权限单独产出结果（但分析缓存跨权限复用）
            roots: dict[str, Any] = {}
            undetermined: list[dict[str, Any]] = []

            # queue item: (current_method, origin_sensitive_method, wrapper_chain, depth)
            queue: deque[tuple[str, str, list[dict[str, Any]], int]] = deque()
            visited: set[tuple[str, str]] = set()

            for origin_method, _hit_list in (methods_dict or {}).items():
                queue.append((origin_method, origin_method, [], 0))
                visited.add((origin_method, origin_method))

            while queue:
                current_method, origin_method, wrapper_chain, depth = queue.popleft()
                analysis = await analyze_method(current_method)

                is_wrapper = analysis.get("is_wrapper_interface")
                if is_wrapper is True:
                    if depth >= recursion_limits["max_depth"]:
                        undetermined.append(
                            {
                                "origin": origin_method,
                                "reason": f"达到 max_depth={recursion_limits['max_depth']}，停止上溯",
                                "last_method": current_method,
                                "wrapper_chain": wrapper_chain
                                + [
                                    {
                                        "method": current_method,
                                        "evidence": analysis.get("evidence"),
                                        "confidence": analysis.get("confidence"),
                                    }
                                ],
                                "hits": methods_dict.get(origin_method, []),
                            }
                        )
                        continue

                    new_chain = wrapper_chain + [
                        {
                            "method": current_method,
                            "evidence": analysis.get("evidence"),
                            "confidence": analysis.get("confidence"),
                        }
                    ]
                    callers: list[str] = analysis.get("callers") or []
                    if not callers:
                        undetermined.append(
                            {
                                "origin": origin_method,
                                "reason": "被判定为通用封装接口，但无法获取调用者，无法继续上溯",
                                "last_method": current_method,
                                "wrapper_chain": new_chain,
                                "hits": methods_dict.get(origin_method, []),
                            }
                        )
                        continue

                    for caller in callers:
                        key = (caller, origin_method)
                        if key in visited:
                            continue
                        visited.add(key)
                        queue.append((caller, origin_method, new_chain, depth + 1))

                elif is_wrapper is False:
                    root_method = current_method
                    roots.setdefault(root_method, {"origins": []})
                    roots[root_method]["origins"].append(
                        {
                            "origin": origin_method,
                            "hits": methods_dict.get(origin_method, []),
                            "wrapper_chain": wrapper_chain,
                            "analysis": {
                                "is_wrapper_interface": False,
                                "confidence": analysis.get("confidence"),
                                "evidence": analysis.get("evidence"),
                            },
                            "call_chain": [
                                origin_method,
                                *[w["method"] for w in wrapper_chain],
                                root_method,
                            ],
                        }
                    )
                else:
                    undetermined.append(
                        {
                            "origin": origin_method,
                            "reason": "无法判定 is_wrapper_interface",
                            "last_method": current_method,
                            "wrapper_chain": wrapper_chain,
                            "hits": methods_dict.get(origin_method, []),
                            "evidence": analysis.get("evidence"),
                        }
                    )

            final_report[permission] = {
                "roots": roots,
                "undetermined": undetermined,
            }

        # Phase 3 (optional): 使用场景符合性审计
        scenarios_by_permission: dict[str, Any] = {}
        if args.scenarios:
            scenarios_by_permission = _read_json_file(args.scenarios)

        if scenarios_by_permission:
            for permission, payload in final_report.items():
                scenarios = scenarios_by_permission.get(permission)
                if not isinstance(scenarios, list) or not scenarios:
                    continue

                wf = per_permission_workflow.get(permission) or {}
                scenario_cfg = wf.get("scenario_check") or {}
                scenario_prompt_template = scenario_cfg.get("system_prompt")
                if not isinstance(scenario_prompt_template, str) or not scenario_prompt_template.strip():
                    # 没有配置场景工作流则跳过
                    continue

                roots_obj = payload.get("roots") or {}
                for root_method, root_info in roots_obj.items():
                    # 根据 origins 的 hits 计算需要注入的 API 文档（只注入命中的那部分）
                    api_docs_all = per_permission_api_docs.get(permission) or {}
                    hit_strings: set[str] = set()
                    for origin_item in (root_info.get("origins") or []):
                        for s in (origin_item.get("hits") or []):
                            hit_strings.add(str(s))
                    api_docs_used = {k: api_docs_all.get(k) for k in hit_strings if api_docs_all.get(k) is not None}

                    context_obj = {
                        "permission": permission,
                        "root_method": root_method,
                        "origins": root_info.get("origins") or [],
                        "api_hits": sorted(list(hit_strings)),
                    }
                    variables = {
                        "input_file": args.apk,
                        "instanceId": instance_id,
                        "permission": permission,
                        "entry_point": root_method,
                        "scenarios_json": json.dumps(scenarios, ensure_ascii=False),
                        "context_json": json.dumps(context_obj, ensure_ascii=False),
                        "api_docs_json": json.dumps(api_docs_used, ensure_ascii=False),
                    }
                    scenario_prompt = _build_scenario_prompt(
                        system_prompt=scenario_prompt_template,
                        rules=scan_manifest.get("rules", []),
                        variables=variables,
                    )

                    resp = await agent.arun(scenario_prompt)
                    txt = getattr(resp, "content", None) or str(resp)
                    scenario_result: dict[str, Any]
                    try:
                        scenario_result = _extract_first_json_object(txt)
                    except Exception:
                        scenario_result = {
                            "entry_point": root_method,
                            "permission": permission,
                            "verdict": "无法判定",
                            "matched_scenarios": [],
                            "confidence": 0.0,
                            "evidence": ["模型输出无法解析为 JSON", txt[:5000]],
                            "issues": ["模型输出格式错误"],
                        }

                    root_info["scenario_check"] = scenario_result

        print(json.dumps(final_report, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())

