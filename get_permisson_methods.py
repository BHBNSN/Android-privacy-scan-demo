import requests
url = "http://localhost:8651"


def get_entry_points(search_string_list, instance_id: str, company: str, base_url: str = url):
    """Search methods containing any of the given strings.

    Returns: {method_signature: [matched_search_string, ...]}
    """
    methods_dict: dict[str, list[str]] = {}

    instanceId = instance_id

    for search_string in search_string_list:
        response_methods = requests.get(
            f"{base_url}/search_string_from_all_classes",
            params={
                "instanceId": instanceId,
                "searchString": search_string,
            },
        ).json().get("result") or []

        for method in response_methods:
            if company not in method:
                continue
            if methods_dict.get(method):
                if search_string not in methods_dict[method]:
                    methods_dict[method].append(search_string)
            else:
                methods_dict[method] = [search_string]

    return methods_dict


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

    company = package.split(".")[1]

    results: dict[str, dict[str, list[str]]] = {}
    for permission, search_strings in permission_search_map.items():
        if not isinstance(search_strings, list) or not search_strings:
            results[permission] = {}
            continue
        results[permission] = get_entry_points(
            search_string_list=search_strings,
            instance_id=instanceId,
            base_url=base_url,
            company=company,
        )

    return results

if __name__ == "__main__":
    methods_dict = collect_permission_methods(
        apk_path="D:\\PyCharmProject\\Android-privacy-scan\\base-3.apk",
        permission_search_map={"location":["clipboard"]},
    )
    print(methods_dict)