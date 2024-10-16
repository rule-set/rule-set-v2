from loguru import logger

import json
import re
import requests
import subprocess
import yaml


class RuleSetConvertor:
    """A class to convert YAML rule sets to JSON format and save them to files."""

    def __init__(self):
        self.field_type_map = {
            "DOMAIN": "domain",
            "HOST": "domain",
            "DOMAIN-SUFFIX": "domain_suffix",
            "HOST-SUFFIX": "domain_suffix",
            "DOMAIN-KEYWORD": "domain_keyword",
            "HOST-KEYWORD": "domain_keyword",
            "host-keyword": "domain_keyword",
            "IP-CIDR": "ip_cidr",
            "ip-cidr": "ip_cidr",
            "IP-CIDR6": "ip_cidr",
            "IP6-CIDR": "ip_cidr",
            "GEOIP": "geoip",
            "DST-PORT": "port",
            "SRC-PORT": "source_port",
            "URL-REGEX": "domain_regex",
            "DOMAIN-REGEX": "domain_regex",
        }

        logger.info("RuleSetConvertor initialized.")

    def convert_yaml_to_json(self, yaml_content, exclude=None):
        """Convert YAML content to JSON format, considering exclude field.

        Args:
            yaml_content (str): The YAML content as a string.
            exclude (str, optional): The value to exclude from the conversion. Defaults to None.

        Returns:
            dict: The converted JSON content as a dictionary.
        """
        try:
            yaml_dict = yaml.safe_load(yaml_content)
            json_content = {}

            for entry in yaml_dict.get("payload", []):
                field_type, value = entry.split(",", 1)
                if exclude and value in exclude:
                    continue
                if field_type in self.field_type_map:
                    json_content.setdefault(self.field_type_map[field_type], []).append(
                        value
                    )
                elif field_type == "IP-ASN":
                    pass
                elif field_type == "PROCESS-NAME":
                    pass
                else:
                    logger.warning(f"Unknown field type: {field_type}")

            return json_content
        except yaml.YAMLError as e:
            logger.error(f"Error converting YAML to JSON: {e}")
            return None

    def get_rule_set(self, url):
        """Fetch the rule set from a given URL.

        Args:
            url (str): The URL to fetch the YAML content from.

        Returns:
            str: The fetched YAML content as a string.
        """
        try:
            response = requests.get(url)
            response.raise_for_status()
            logger.info(f"Successfully fetched rule set from {url}")
            if url.endswith(".json"):
                json_content = response.json()
                return json_content
            elif url.endswith(".yaml"):
                yaml_content = response.content.decode("utf-8")
                return yaml_content
            elif url.endswith(".srs"):
                return response.content
        except requests.RequestException as e:
            logger.error(f"Error fetching rule set from {url}: {e}")
            return None

    def get_rule_set_list(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            logger.info(f"Successfully fetched rule set from {url}")
            data = response.text
            payload = []
            for line in data.splitlines():
                if line.startswith("#") or "payload:" in line:
                    continue
                line = re.sub(r"'$", "", line)
                line = line.lstrip()
                line = re.sub(r"^- '\+\.", "DOMAIN-SUFFIX,", line)
                line = re.sub(r"^- '", "DOMAIN,", line)
                if line:
                    payload.append(line)

            yaml_data = {"payload": payload}
            return yaml.dump(yaml_data, default_flow_style=False)
        except requests.RequestException as e:
            logger.error(f"Error fetching rule set from {url}: {e}")
            return None

    def save_to_file(self, content, file_name, file_extension):
        """Save content to a file with the specified name and extension.

        Args:
            content (dict or bytes): The content to save.
            file_name (str): The name of the file.
            file_extension (str): The extension of the file.
        """
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(f"{file_name}.{file_extension}", mode) as file:
            if file_extension == "json":
                json.dump(content, file, indent=4)
            else:
                file.write(content)
        logger.info(f"Successfully saved {file_name}.{file_extension}")

    def compile_json(self, file_name):
        """Compile JSON file using sing-box command.

        Args:
            file_name (str): The name of the JSON file to compile.
        """
        try:
            subprocess.run(
                ["./compiler", "rule-set", "compile", f"{file_name}.json"], check=True
            )
            logger.info(f"Successfully compiled {file_name}.json")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error compiling {file_name}.json: {e}")

    def run(self, rules):
        """Run the conversion process for the provided rules.

        Args:
            rules (dict): A dictionary containing YAML and SRS rules.
        """
        for rule in rules.get("list", []):
            logger.info(f"Processing rule: {rule['fileName']}")

            combined_json_content = {"version": 1, "rules": [{}]}

            for url in rule.get("url", []):
                list_content = self.get_rule_set_list(url)
                if list_content:
                    json_content = self.convert_yaml_to_json(
                        list_content, exclude=rule.get("exclude")
                    )
                    if json_content:
                        for key, values in json_content.items():
                            combined_json_content["rules"][0].setdefault(
                                key, []
                            ).extend(values)

            if "custom" in rule:
                for custom_item in rule["custom"]:
                    for key, values in custom_item.items():
                        # for v in values:
                        combined_json_content["rules"][0].setdefault(key, []).extend(
                            values
                        )

        self.save_to_file(combined_json_content, rule["fileName"], "json")
        self.compile_json(rule["fileName"])

        for rule in rules.get("json", []):
            logger.info(f"Processing rule: {rule['fileName']}")

            for url in rule.get("url", []):
                json_content = self.get_rule_set(url)
                if json_content:
                    exclude = rule.get("exclude", "")
                    if exclude != "":
                        for key, values in json_content["rules"][0].items():
                            intersection = set(exclude).intersection(set(values))
                            if intersection:
                                for i in intersection:
                                    json_content["rules"][0][key].remove(i)

            if "custom" in rule:
                for custom_item in rule["custom"]:
                    for key, values in custom_item.items():
                        json_content["rules"][0].setdefault(key, []).extend(values)

            json_content["version"] = 1
            self.save_to_file(json_content, rule["fileName"], "json")
            self.compile_json(rule["fileName"])

        for rule in rules.get("yaml", []):
            logger.info(f"Processing rule: {rule['fileName']}")

            combined_json_content = {"version": 1, "rules": [{}]}

            for url in rule.get("url", []):
                yaml_content = self.get_rule_set(url)
                if yaml_content:
                    json_content = self.convert_yaml_to_json(
                        yaml_content, exclude=rule.get("exclude")
                    )
                    if json_content:
                        for key, values in json_content.items():
                            combined_json_content["rules"][0].setdefault(
                                key, []
                            ).extend(values)

            if "custom" in rule:
                for custom_item in rule["custom"]:
                    for key, values in custom_item.items():
                        # for v in values:
                        combined_json_content["rules"][0].setdefault(key, []).extend(
                            values
                        )

            self.save_to_file(combined_json_content, rule["fileName"], "json")
            self.compile_json(rule["fileName"])

        for rule in rules.get("srs", []):
            logger.info(f"Processing rule: {rule['fileName']}")

            srs_content = self.get_rule_set(rule["url"])
            if srs_content:
                self.save_to_file(srs_content, rule["fileName"], "srs")


if __name__ == "__main__":
    with open("rules.json", "r") as f:
        rules = json.load(f)
    convertor = RuleSetConvertor()
    convertor.run(rules)
