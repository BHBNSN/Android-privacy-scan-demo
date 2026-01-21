import requests
import json
url = "http://localhost:8651"

all_root = set()
all_calls = {}
all_use = {}
not_get_call = set()

def get_method_call(instance_id: str, method_signature: str, base_url: str = url):
    """Get method call information for a given method signature."""
    instanceId = instance_id

    response = requests.get(
        f"{base_url}/get_method_callers",
        params={
            "instanceId": instanceId,
            "methodName": method_signature,
        },
    ).json()

    print(response)

    result = response.get("result")

    if type(result) is not list or len(result) == 0:
        all_root.add(method_signature)
    else:
        global not_get_call
        for method in result:
            not_get_call.add(method)
        if all_calls.get(method_signature):
            all_calls[method_signature].extend(result)
        else:
            all_calls[method_signature] = result

    print(all_calls)


def get_entry_points(search_string_list, instance_id: str, company: str, base_url: str = url):
    """Search methods containing any of the given strings.

    Returns: {method_signature: [matched_search_string, ...]}
    """
    instanceId = instance_id

    response_methods = requests.get(
        f"{base_url}/search_strings_from_all_classes",
        params={
            "instanceId": instanceId,
            "searchStrings": json.dumps(search_string_list),
        },
    ).json().get("result") or []

    result = {}

    for method , strings in response_methods.items():
        if method.startswith(f"{company}"):
            result[method] = strings

    return result


def collect_permission_methods(
    apk_path: str,
    permission_search_map: dict[str, list[str]],
    base_url: str = url,
):
    """Collect entry methods per permission using a single load() call.

    Returns:
      {
        permission: {
          method_signature: [matched_search_string, ...]
        }
      }
    """
    instanceId = requests.get(
        f"{base_url}/load",
        params={
            "filePath": apk_path
        },
    ).json().get("result")

    print(instanceId)

    manifest = requests.request("GET", url + "/get_manifest", params={"instanceId": instanceId}).json()["result"]

    package = manifest.split('package=')[1].split('\n')[0].replace('"', '').strip()

    company = package.split(".")[0] + '.' + package.split(".")[1]

    all_search_strings = []
    for permission, search_strings in permission_search_map.items():
        all_search_strings.extend(search_strings)


    all_results = get_entry_points(
        search_string_list=all_search_strings,
        instance_id=instanceId,
        base_url=base_url,
        company=company,
    )
    global all_use, not_get_call
    all_use = all_results

    for method, strings in all_results.items():
        not_get_call.add(method)

    while len(not_get_call) > 0:
        get_method_call(instance_id=instanceId, method_signature=not_get_call.pop())


    print(all_root)
    print(all_calls)

if __name__ == "__main__":
    collect_permission_methods(
        apk_path="D:\\PyCharmProject\\Android-privacy-scan\\base-3.apk",
        permission_search_map={"location":["location.get","location.getProvider"]},
    )