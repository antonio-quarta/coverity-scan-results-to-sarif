import argparse
import sys

from .converter import convert_to_sarif


def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert Coverity JSON results to SARIF 2.1.0")
    parser.add_argument("input_json", help="Coverity cov-format-errors JSON file")
    parser.add_argument("output_sarif", help="Path for the generated SARIF file")
    args = parser.parse_args(argv)

    try:
        sarif = convert_to_sarif(args.input_json, args.output_sarif)
    except (OSError, ValueError) as error:
        print("Error: {}".format(error), file=sys.stderr)
        return 1

    result_count = len(sarif["runs"][0]["results"])
    print("Issues count: {}".format(result_count))
    print("SARIF file created: {}".format(args.output_sarif))
    return 0