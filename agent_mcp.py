import asyncio
import os
import argparse
import json
import re
from dataclasses import dataclass
from typing import Any, Optional

import requests

from agno.agent import Agent  # type: ignore
from agno.models.openai import OpenAIChat  # type: ignore
from agno.tools.mcp import MCPTools  # type: ignore
from mcp import StdioServerParameters  # type: ignore
_HAS_AGNO = True

from get_permisson_methods import collect_permission_methods


SCAN_MANIFEST_PATH = "scan_manifest.json"
SCENARIOS_PATH = "per.json"
JADX_DAEMON_URL = "http://localhost:8651"

# 权限检测顺序（避免混淆）
PERMISSION_ORDER = ["location", "clipboard"]


def _log(msg: str) -> None:
    print(msg, flush=True)


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


def _safe_get_json(resp: requests.Response) -> dict:
    try:
        return resp.json() or {}
    except Exception:
        return {}


def _jadx_load(*, jadx_daemon_url: str, apk_path: str) -> str:
    data = _safe_get_json(
        requests.get(
            f"{jadx_daemon_url}/load",
            params={"filePath": apk_path},
            timeout=120,
        )
    )
    instance_id = str(data.get("result") or "").strip()
    if not instance_id:
        raise RuntimeError("JADX daemon load() 未返回有效 instanceId")
    return instance_id


@dataclass
class OpenAICompatClient:
    base_url: str
    api_key: str
    model: str

    def chat(self, *, prompt: str) -> str:
        url = self.base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=180)
        data = _safe_get_json(resp)
        try:
            return str(data["choices"][0]["message"]["content"])
        except Exception:
            raise RuntimeError(f"LLM 返回异常: {data}")


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


def _build_global_scenario_prefix(scan_manifest: dict) -> str:
    """Global prefix for scenario checking prompts (non-authoritative)."""
    prefix = scan_manifest.get("scenario_global_prompt")
    if isinstance(prefix, str) and prefix.strip():
        return prefix.strip()
    # fallback (keep concise)
    return (
        "【全局约束补充】\n"
        "- 你收到的 context_json 是自动预提取的调用链/命中信息，可能因匿名类/反射/动态代理/跨进程等原因不完整。\n"
        "- 不得把 context_json 当成完整事实；必须在需要时继续使用 JADX MCP 追踪/搜索/反编译以补全证据。\n"
    )

async def main():
    parser = argparse.ArgumentParser(description="Android privacy scenario audit agent")
    parser.add_argument("--apk", required=True, help="待分析的 APK 路径")
    args = parser.parse_args()

    # 运行配置（写死，避免命令行参数混淆）
    scan_manifest_path = SCAN_MANIFEST_PATH
    scenarios_path = SCENARIOS_PATH
    jadx_daemon_url = JADX_DAEMON_URL

    llm_base_url = os.getenv("OPENAI_BASE_URL", "https://www.dmxapi.cn/v1")
    llm_model = os.getenv("OPENAI_MODEL", "GLM-4.5-Flash")

    mcp_tools = None
    if _HAS_AGNO:
        assert StdioServerParameters is not None
        assert MCPTools is not None
        jadx_mcp_server = os.getenv("JADX_MCP_SERVER", r"D:\\JAVAProjects\\jadx-daemon-mcp\\server.py")
        jadx_host = os.getenv("JADX_DAEMON_MCP_HOST", "localhost")
        # Define the MCP server configuration
        server_params = StdioServerParameters(
            command="python",
            args=[jadx_mcp_server],
            env={"JADX_DAEMON_MCP_HOST": jadx_host},
        )
        mcp_tools = MCPTools(
            transport="stdio",
            server_params=server_params,
        )

    # Initialize the Agent with the MCP tools
    # IMPORTANT: never hard-code API keys in source code.
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("DMX_API_KEY")
    if not api_key:
        raise RuntimeError("未检测到 OPENAI_API_KEY（或 DMX_API_KEY）环境变量。")

    scan_manifest = _read_json_file(scan_manifest_path)
    permission_workflows = scan_manifest.get("permission_workflows") or {}
    if not isinstance(permission_workflows, dict) or not permission_workflows:
        raise RuntimeError("scan_manifest.json 未配置 permission_workflows")

    recursion_limits = _get_recursion_limits(scan_manifest)

    # load once, reuse instanceId
    _log(f"[agent] load APK -> instanceId: {args.apk}")
    instance_id = _jadx_load(jadx_daemon_url=jadx_daemon_url, apk_path=args.apk)
    _log(f"[agent] instanceId={instance_id}")

    # LLM client (fallback when agno not installed)
    llm_client: Optional[OpenAICompatClient] = None
    if not _HAS_AGNO:
        llm_client = OpenAICompatClient(base_url=llm_base_url, api_key=api_key, model=llm_model)

    # 读取外部声明的使用场景（permission -> list[str]）
    scenarios_by_permission: dict[str, Any] = {}
    if os.path.exists(scenarios_path):
        scenarios_by_permission = _read_json_file(scenarios_path)

    async def _run_with_agno():
        assert _HAS_AGNO and mcp_tools is not None
        assert Agent is not None
        assert OpenAIChat is not None
        agent = Agent(
            model=OpenAIChat(
                id=llm_model,
                base_url=llm_base_url,
                api_key=api_key,
            ),
            tools=[mcp_tools],
            markdown=True,
            debug_mode=True,
            system_message_role="user",
        )

        print("Starting agent with MCP tools...")
        async with mcp_tools:
            print(f"Tools available: {len(mcp_tools.functions)}")
            async def agent_call(prompt: str):
                return await agent.arun(prompt)

            await _run_all_permissions(agent_call=agent_call)

    async def _run_without_agno():
        client = llm_client
        assert client is not None

        def agent_call(prompt: str):
            return client.chat(prompt=prompt)

        await _run_all_permissions(agent_call=agent_call)

    async def _run_one_permission(*, permission: str, agent_call) -> tuple[str, dict[str, Any]] | None:
        workflow_path = permission_workflows.get(permission)
        if not workflow_path:
            return None

        _log(f"[agent] ===== permission={permission} =====")

        wf = _read_json_file(str(workflow_path))
        search_strings = wf.get("search_strings") or []
        if not isinstance(search_strings, list) or not search_strings:
            return None

        scenario_cfg = wf.get("scenario_check") or {}
        scenario_prompt_template = scenario_cfg.get("system_prompt")
        if not isinstance(scenario_prompt_template, str) or not scenario_prompt_template.strip():
            return None

        api_docs_raw = wf.get("api_docs")
        api_docs_all: dict[str, Any] = api_docs_raw if isinstance(api_docs_raw, dict) else {}
        scenarios = scenarios_by_permission.get(permission)
        if not isinstance(scenarios, list):
            scenarios = []

        # 每次只传入一个大权限的 map，避免混淆
        permission_search_map = {permission: [str(s) for s in search_strings if str(s).strip()]}
        _log(f"[agent] extract call graph: permission={permission} search_strings={len(permission_search_map[permission])}")
        extracted = collect_permission_methods(
            apk_path=args.apk,
            permission_search_map=permission_search_map,
            instance_id=instance_id,
            recursion_limits=recursion_limits,
            base_url=jadx_daemon_url,
            verbose=True,
        )
        perm_obj = (extracted.get("by_permission") or {}).get(permission) or {}
        if not isinstance(perm_obj, dict) or not (perm_obj.get("hits") and perm_obj.get("roots_index")):
            return (
                permission,
                {
                    "extracted": perm_obj,
                    "scenario_results": {},
                },
            )

        hits = perm_obj.get("hits") or {}
        roots_index = perm_obj.get("roots_index") or {}
        call_graph = perm_obj.get("call_graph") or {}

        _log(
            f"[agent] extracted: permission={permission} hits={len(hits)} roots={len(roots_index)} edges={len((call_graph or {}).get('edges') or [])}"
        )

        global_prefix = _build_global_scenario_prefix(scan_manifest)
        effective_template = f"{global_prefix}\n\n{scenario_prompt_template}"

        perm_report: dict[str, Any] = {
            "extracted": {
                "hits": hits,
                "call_graph": call_graph,
                "roots_index": roots_index,
            },
            "scenario_results": {},
        }

        root_items = list((roots_index or {}).items())
        for idx, (root_method, root_info) in enumerate(root_items, start=1):
            _log(f"[agent] scenario_check {permission}: {idx}/{len(root_items)} root={root_method}")
            # 只注入命中的 API docs
            hit_strings: set[str] = set()
            sink_hits = (root_info or {}).get("sink_hits") or {}
            if isinstance(sink_hits, dict):
                for _sink, arr in sink_hits.items():
                    if isinstance(arr, list):
                        for s in arr:
                            hit_strings.add(str(s))
            api_docs_used = {k: api_docs_all.get(k) for k in hit_strings if api_docs_all.get(k) is not None}

            context_obj = {
                "permission": permission,
                "root_method": root_method,
                "sinks": (root_info or {}).get("sinks") or [],
                "sink_hits": sink_hits,
                "paths": (root_info or {}).get("paths") or [],
                "graph_limits": (call_graph or {}).get("limits") or {},
                "notice": "context_json 为自动预提取线索，可能不完整；需要用 JADX MCP 扩展验证",
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
                system_prompt=effective_template,
                rules=scan_manifest.get("rules", []),
                variables=variables,
            )

            resp = agent_call(scenario_prompt)
            if asyncio.iscoroutine(resp):
                resp = await resp
            txt = getattr(resp, "content", None) or str(resp)
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

            perm_report["scenario_results"][root_method] = scenario_result

        return permission, perm_report

    async def _run_all_permissions(agent_call):
        final_report: dict[str, Any] = {
            "instanceId": instance_id,
            "apk": args.apk,
            "by_permission": {},
        }

        for permission in PERMISSION_ORDER:
            item = await _run_one_permission(permission=permission, agent_call=agent_call)
            if not item:
                continue
            perm, report = item
            final_report["by_permission"][perm] = report

        print(json.dumps(final_report, ensure_ascii=False))

    if _HAS_AGNO:
        await _run_with_agno()
    else:
        await _run_without_agno()

if __name__ == "__main__":
    asyncio.run(main())

