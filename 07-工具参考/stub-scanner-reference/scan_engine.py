"""Run the read-only stub scanner with a user-supplied engine profile."""

import argparse
import json
from pathlib import Path

from core.arg_stub import arg_stub_range, find_arg_stub_cores
from core.pe import load_pe
from core.stub_scan import get_skill_name, scan_stubs


def _va(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"invalid VA value: {value!r}")


def _read_profile(path):
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    ranges = []
    for item in profile.get("dispatch_ranges", []):
        start, end = _va(item["start"]), _va(item["end"])
        if start >= end:
            raise ValueError("each dispatch range must have start < end")
        ranges.append((start, end, str(item.get("label", "dispatch"))))
    targets = {_va(value) for value in profile.get("inline_core_targets", [])}
    body = profile.get("dispatch_body")
    if body is not None:
        body = (_va(body["start"]), _va(body["end"]))
        if body[0] >= body[1]:
            raise ValueError("dispatch_body must have start < end")
    if not ranges and not targets:
        raise ValueError("profile needs at least one dispatch range or inline core target")
    name_table = profile.get("skill_name_table_va")
    return ranges, targets, body, _va(name_table) if name_table is not None else None


def main():
    parser = argparse.ArgumentParser(
        description="Read-only x86 PE stub candidate scanner; results require manual review."
    )
    parser.add_argument("engine", help="path to the PE32 x86 file to inspect")
    parser.add_argument("--profile", required=True, help="JSON with target-specific call targets")
    parser.add_argument("--output", help="write JSON results to this file; default is stdout")
    args = parser.parse_args()

    try:
        dispatch_ranges, targets, dispatch_body, _name_table = _read_profile(args.profile)
        data, sections = load_pe(args.engine)
        stubs = scan_stubs(args.engine, dispatch_ranges, targets, dispatch_body)
        if _name_table is not None:
            for stub in stubs:
                if stub["per"] is not None:
                    stub["name"] = get_skill_name(data, sections, stub["per"], _name_table)
        arg_cores = find_arg_stub_cores(data, sections, targets)
        arg_ranges = []
        for core in sorted(arg_cores):
            value_range = arg_stub_range(data, sections, core)
            arg_ranges.append({
                "core_va": core,
                "candidate_range": list(value_range) if value_range else None,
            })
        result = {
            "engine_file": Path(args.engine).name,
            "stubs": stubs,
            "arg_stub_ranges": arg_ranges,
            "notes": [
                "Static pattern matches are candidates, not confirmed engine behavior.",
                "Check every address, call path, and inferred argument against the inspected file.",
                "Source-defined and code-cave-only stub formats are not included in this reference.",
            ],
        }
        rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            output_path = Path(args.output).resolve()
            if output_path == Path(args.engine).resolve():
                raise ValueError("output path must not be the inspected engine file")
            output_path.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
