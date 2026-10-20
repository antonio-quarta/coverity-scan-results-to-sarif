import json
from pathlib import Path
from urllib.parse import quote


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def impact_to_level(impact):
    return {
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }.get(impact, "none")


def _rule_id(issue, checker_properties):
    cwe_category = checker_properties.get("cweCategory")
    if cwe_category is not None and str(cwe_category):
        return str(cwe_category)
    return str(issue.get("checkerName") or issue.get("type") or "coverity-issue")


def _make_rule(rule_id, checker_properties):
    cwe_category = checker_properties.get("cweCategory")
    short_description = checker_properties.get("subcategoryShortDescription") or rule_id
    long_description = checker_properties.get("subcategoryLongDescription") or short_description

    if cwe_category is not None:
        short_description = "CWE-{}: {}".format(cwe_category, short_description)
        long_description = "CWE-{}: {}".format(cwe_category, long_description)

    rule = {
        "id": rule_id,
        "shortDescription": {"text": short_description},
        "help": {"text": long_description},
        "defaultConfiguration": {
            "level": impact_to_level(checker_properties.get("impact"))
        },
    }

    if cwe_category is not None:
        rule["helpUri"] = "https://cwe.mitre.org/data/definitions/{}.html".format(cwe_category)
    if checker_properties.get("category") is not None:
        rule["properties"] = {"category": checker_properties["category"]}

    return rule


def _location(issue):
    events = issue.get("events")
    main_event = None
    if isinstance(events, list):
        main_event = next(
            (event for event in events if isinstance(event, dict) and event.get("main") is True),
            None,
        )

    if main_event is not None:
        file_path = main_event.get("strippedFilePathname") or main_event.get("filePathname")
        line_number = main_event.get("lineNumber")
    else:
        file_path = issue.get("strippedMainEventFilePathname") or issue.get("mainEventFilePathname")
        line_number = issue.get("mainEventLineNumber")

    if not file_path:
        return None

    physical_location = {
        "artifactLocation": {
            "uri": quote(str(file_path).replace("\\", "/"), safe="/:!$&'()*+,;=@-._~")
        }
    }
    try:
        line_number = int(line_number)
    except (TypeError, ValueError):
        line_number = None
    if line_number is not None and line_number > 0:
        physical_location["region"] = {"startLine": line_number}

    return {"physicalLocation": physical_location}


def _message(issue, checker_properties):
    events = issue.get("events")
    descriptions = []
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("main") is True or event.get("eventTag") == "remediation":
                description = event.get("eventDescription")
                if description:
                    descriptions.append(str(description))

    return "".join(descriptions) or checker_properties.get("subcategoryLongDescription") or issue.get("checkerName") or "Coverity issue"


def convert_to_sarif(input_file, output_file):
    with Path(input_file).open("r", encoding="utf-8") as source:
        coverity_results = json.load(source)

    if not isinstance(coverity_results, dict) or not isinstance(coverity_results.get("issues"), list):
        raise ValueError("Coverity results must be a JSON object containing an issues array")

    rules = []
    rules_by_id = {}
    sarif_results = []

    for index, issue in enumerate(coverity_results["issues"]):
        if not isinstance(issue, dict):
            raise ValueError("Coverity issue at index {} must be a JSON object".format(index))

        checker_properties = issue.get("checkerProperties")
        if not isinstance(checker_properties, dict):
            checker_properties = {}

        rule_id = _rule_id(issue, checker_properties)
        if rule_id not in rules_by_id:
            rule = _make_rule(rule_id, checker_properties)
            rules_by_id[rule_id] = rule
            rules.append(rule)

        result = {
            "level": impact_to_level(checker_properties.get("impact")),
            "message": {"text": _message(issue, checker_properties)},
            "ruleId": rule_id,
        }
        location = _location(issue)
        if location is not None:
            result["locations"] = [location]
        sarif_results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Coverity Static Analysis Results",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    Path(output_file).write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return sarif