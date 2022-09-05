import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import date, datetime
from io import StringIO
from json.decoder import JSONDecodeError
from typing import TYPE_CHECKING

import jinja2
import requests
import yaml
from jinja2 import Environment, FileSystemLoader
from requests_toolbelt import MultipartEncoder
from yaml.parser import ParserError
from yaml.scanner import ScannerError
import math


# Disable urllib3 warning when https is used with self-signed certificate
requests.packages.urllib3.disable_warnings()

# Tool Telemetry Information (used to provide information about missing templates)
telemetry_url = "http://cx-emear-tools-stats.cisco.com/tool_telemetry/"
telemetry_timeout = 2


class TemplateRender(object):
    """Template rendering Class which use jinja2 Templating language
    The class constructor takes the path to the xml template directory as input data
    The file names in the directory are loaded in a dictionary structure
    The class provides the  method render_template for rendering a template
    """

    def __init__(self, template_path):
        self.jinja_env = self.create_jinja_env(template_path)
        self.template_dict = self.load_template(template_path)

    def create_jinja_env(self, template_path):
        template_loader = FileSystemLoader(searchpath=template_path)
        template_env = Environment(
            loader=template_loader, trim_blocks=True, lstrip_blocks=True
        )
        return template_env

    def load_template(self, template_path):
        logger = logging.getLogger(__name__)
        try:
            template_dict = {}
            files = os.listdir(template_path)
            for template in files:
                filename = template.split(".")
                fo = open(template_path + template, "r")
                template_dict[filename[0]] = fo.read()
            return template_dict
        except OSError:
            logger.critical("Can't find template directory %s " % template_path)
            sys.exit(1)
        except Exception as e:
            logger.critical(
                "Undefined error in loading templates in '{}': {}".format(
                    template_path, e
                )
            )
            sys.exit(1)

    def render_template(self, template_file, item):
        """Takes as argument
        The name of the template file to be used : template_file
        The data input dictionary  used to render the template: item
        """
        logger = logging.getLogger(__name__)
        try:
            logger.debug("Rendering template: {}".format(template_file))
            template = self.jinja_env.get_template(template_file)
            rendered_output = template.render(item)
            return (True, rendered_output)
        except jinja2.TemplateNotFound:
            logger.error("Template missing '%s'" % template_file)
            logger.debug(
                "Item that was attempted to be rendered against non-existing template: %s"
                % item
            )
            telemetry_message = {
                "timestamp": str(datetime.now()),
                "toolName": "aci_proactive_audit",
                "exception": "TemplateNotFound",
                "template": template_file,
                "data": item,
            }
            submit_telemetry(telemetry_message)
            return (False, "Template missing '%s'" % template_file)
        except jinja2.TemplateSyntaxError as e:
            message = "Syntax error in Template '%s' " % template_file
            error_line = str(e.message) + " line number : " + str(e.lineno)
            logger.error(message + " " + error_line)
            telemetry_message = {
                "timestamp": str(datetime.now()),
                "toolName": "aci_proactive_audit",
                "exception": "TemplateSyntaxError",
                "template": template_file,
                "data": item,
            }
            submit_telemetry(telemetry_message)
            return (False, message)
        except Exception:
            logger.critical(
                "Undefined error while rendering template '%s'" % template_file
            )
            telemetry_message = {
                "timestamp": str(datetime.now()),
                "toolName": "aci_proactive_audit",
                "exception": "TemplateUndefinedError",
                "template": template_file,
                "data": item,
            }
            submit_telemetry(telemetry_message)
            return (
                False,
                "Undefined error while rendering template '%s'" % template_file,
            )


def telemetry_remove_customer_data(input_data: dict):

    # Check if telemetry has the format of template missing
    if "template" in input_data.keys():
        # Copy non-data keys over
        __output_data = dict()
        __output_data["timestamp"] = input_data["timestamp"]
        __output_data["toolName"] = input_data["toolName"]
        __output_data["exception"] = input_data["exception"]
        __output_data["template"] = input_data["template"]

        # Iterate through message and remove customer sensitive data
        if input_data["template"].startswith("nae"):
            __output_data["data"] = dict()
            __output_data["data"]["event_list"] = list()

            for __input_entry in input_data["data"]["event_list"]:
                __output_subentries = list()
                for __input_subentry in __input_entry:
                    __output_subentry = dict()
                    if "identifier" in __input_subentry:
                        __output_subentry["identifier"] = "<removed>"
                    if "object_types" in __input_subentry:
                        __output_subentry["object_types"] = __input_subentry["object_types"]
                    if "objectType" in __input_subentry:
                        __output_subentry["objectType"] = __input_subentry["objectType"]
                    if "name" in __input_subentry:
                        __output_subentry["name"] = "<removed>"
                    if "objectValue" in __input_subentry:
                        __output_subentry["objectValue"] = "<removed>"
                    __output_subentries.append(__output_subentry)

                __output_data["data"]["event_list"].append(__output_subentries)

        elif input_data["template"].startswith("vetR"):
            __output_data["data"] = "<removed>"

        return __output_data
    else:
        # Unrecognized telemetry format, return input unmodified
        return input_data


def submit_telemetry(message: dict):
    logger = logging.getLogger(__name__)

    if not INCOGNITO_EXEC_MODE:
        try:
            headers = {"Content-type": "application/json", "Accept": "text/plain"}
            message = telemetry_remove_customer_data(message)
            payload = json.dumps(message)
            http_post = requests.post(
                telemetry_url,
                data=payload,
                headers=headers,
                verify=False,
                timeout=telemetry_timeout,
            )
            if http_post.status_code != 200:
                logger.debug(
                    "Failed to submit telemetry information, HTTP status-code %s"
                    % http_post.status_code
                )
            else:
                logger.debug("Successful submition of telemetry information")
        except requests.exceptions.Timeout:
            logger.debug("Failed to submit telemetry information, HTTP timeout")
        except requests.exceptions.ConnectionError:
            logger.debug(
                "Failed to submit telemetry information, HTTP connection error"
            )
    else:
        logger.debug(
            "SKIPPING submission of telemetry information as script is run in incognito mode"
        )


def verify_input_parameters(__input: dict):
    """
    Verifies that all the required input parameters has been provieded.
    If this is not the case, then the user will be prompted for them.

    Inputs:
      __input - dictionary with all argparse arguments

    Returns:
      __input - updated dictionary with all missing parameters in addition to the argparse parameters
    """

    # Convert input for enable_vetr to bool expression
    if str(__input["enable_vetr"]).lower() == "false":
        __input["enable_vetr"] = False
    else:
        __input["enable_vetr"] = True

    # Convert input for enable_nae to bool expression
    if str(__input["enable_nae"]).lower() == "false":
        __input["enable_nae"] = False
    else:
        __input["enable_nae"] = True

    # Convert input for enable_ssd to bool expression
    if str(__input["enable_ssd"]).lower() == "false":
        __input["enable_ssd"] = False
    else:
        __input["enable_ssd"] = True

    # Engineer name - skip check if output is json as info is used in final report only
    if "engineer_name" not in __input:
        __input["engineer_name"] = None
    if __input["engineer_name"] is None and (
        "import_findings" in __input["tasks"] or "export_findings" in __input["tasks"]
    ):
        __input["engineer_name"] = ""
    elif __input["engineer_name"] is None:
        __txt = input("Please enter your name: ")
        __input["engineer_name"] = __txt

    # Customer name - skip check if output is json as info is used in final report only
    if "customer_name" not in __input:
        __input["customer_name"] = None
    if __input["customer_name"] is None and (
        "import_findings" in __input["tasks"] or "export_findings" in __input["tasks"]
    ):
        __input["customer_name"] = ""
    elif __input["customer_name"] is None:
        __txt = input("Please enter customer name: ")
        __input["customer_name"] = __txt

    # PID - skip check if output is json as info is used in final report only
    if "pid" not in __input:
        __input["pid"] = None
    if __input["pid"] is None and (
        "import_findings" in __input["tasks"] or "export_findings" in __input["tasks"]
    ):
        __input["pid"] = ""
    elif __input["pid"] is None:
        __txt = input("Please enter pid: ")
        __input["pid"] = __txt

    # Check NAE parameters when enabled
    if __input["enable_nae"] and "get_findings" in __input["tasks"]:
        # NAE Hostname
        if __input["nae_hostname"] is None:
            __txt = input("Please enter NAE hostname: ")
            __input["nae_hostname"] = __txt

        # NAE Username
        if __input["nae_username"] is None:
            __txt = input("Please enter NAE username: ")
            __input["nae_username"] = __txt

        # NAE Password
        if __input["nae_password"] is None:
            __txt = input("Please enter NAE password: ")
            __input["nae_password"] = __txt

        # NAE Assurance Group
        if __input["nae_assurance_group"] is None:
            __txt = input("Please enter NAE Assurance Group: ")
            __input["nae_assurance_group"] = __txt

        # NAE Version
        if "nae_version" not in __input:
            # default to NAE for now
            __input["nae_version"] = "nae"

        if __input["nae_version"] is None:
            __txt = input("Please specify NAE version (nae or ndi): ")
            if __txt.lower() not in ["nae", "ndi"]:
                logging.error("Invalid NAE version specified, exiting.")
                exit(1)
            __input["nae_version"] = __txt.lower()
    else:
        __input["nae_hostname"] = None
        __input["nae_username"] = None
        __input["nae_password"] = None
        __input["nae_assurance_group"] = None
        __input["nae_version"] = None

    # Check SSD input file
    if __input["enable_ssd"] and "get_findings" in __input["tasks"]:
        if __input["ssd_input"] is None:
            __txt = input("Please specify SSD Script Report file: ")
            __input["ssd_input"] = __txt

    # Define default findings_input parameter
    if "findings_input" not in __input:
        __input["findings_input"] = "aci_audit_output.json"

    # Return script parameters
    return __input


def get_subdir(__path: str):
    """
    Generates a list of all subdirectoires of the provided path.

    Inputs:
      __path - String containing the path that could be checked for subdirectories

    Returns:
      __subdir - List of subdirectories under the specified path
    """
    logger = logging.getLogger(__name__)
    __subdir = []
    __dir_content = os.listdir(__path)
    logger.debug("Directory Content of '{}' is: {}".format(__path, __dir_content))
    for __item in __dir_content:
        if os.path.isdir(os.path.join(__path, __item)):
            __subdir.append(__item)

    logger.debug(
        "The following subdirectorie exist under '{}': {}".format(__path, __subdir)
    )
    return __subdir


def get_nested_dict_entries_containing_key(__var, __key, __path=[]):
    """
    Traverse nested dictionary to find all paths where the specified key is found

    Inputs:
      __var - Nested dictionary
      __key - Search Key
      __paths - Path in__side nested dictionary, not mandatory when calling the function

    Returns:
      Generator that yields the path and dictionary entries where __key is found

    """
    if isinstance(__var, dict):
        if __key in __var.keys():
            yield (__path, __var)
        else:
            for k, v in __var.items():
                if isinstance(v, (dict, list)):
                    __path.append(k)
                    yield from get_nested_dict_entries_containing_key(v, __key, __path)

    elif isinstance(__var, list):
        for d in __var:
            __path.append(d)
            yield from get_nested_dict_entries_containing_key(d, __key, __path)

    if len(__path) > 0:
        __path.pop()


def read_json(file: StringIO):
    """
    Reads JSON file and returns corresponding dictionary

    In case of failure will an exception be raised

    Input:
      file - JSON file to be read

    Output:
       __data - dictionary representation of the JSON input
    """
    logger = logging.getLogger(__name__)
    try:
        __f = open(file, mode="r", encoding="utf-8")
        __data = json.load(__f)
        __f.close
        return __data
    except FileNotFoundError:
        logger.critical("Unable to read JSON file '%s', exiting..." % file)
        exit(1)
    except JSONDecodeError:
        logger.critical("Unable to decode JSON file '%s', exiting..." % file)
        exit(1)


def read_yaml(file: StringIO):
    """
    Reads YAML file and returns corresponding dictionary

    In case of failure will an exception be raised

    Input:
      file - YAML file to be read

    Output:
       __data - dictionary representation of the YAML input
    """
    logger = logging.getLogger(__name__)
    try:
        with open(file, "r", encoding="utf-8") as f:
            __data = yaml.load(f, Loader=yaml.BaseLoader)
        return __data
    except FileNotFoundError:
        logger.critical("Unable to read YAML file '%s', exiting..." % file)
        exit(1)
    except ScannerError:
        logger.critical("Unable to decode YAML file '%s', exiting..." % file)
        exit(1)
    except ParserError:
        logger.critical("Unable to decode YAML file '%s', exiting..." % file)
        exit(1)


def read_txt(file: StringIO):
    """
    Reads TXT file into a string

    In case of failure will an exception be raised

    Input:
      file - TXT file to be read

    Output:
       __data - list representation of the TXT input
    """
    logger = logging.getLogger(__name__)
    try:
        with open(file, "r", encoding="utf-8") as f:
            __data = f.readlines()
        return __data
    except FileNotFoundError:
        logger.critical("Unable to read TXT file '%s', exiting..." % file)
        exit(1)


def get_template_metadata(template_content: str, template_file: str):
    """
    Extracts template metadata from rendered markdown template file.

    The metadata will be stored within a <!--- --> commnet
    section at the top of the template file.

    Example:
    <!--
    category: health_check
    severity: notice
    -->

    Input:
        template_content - content of the rendered template file
        template_file - Filename of markdown template file

    Output:
        __success - True or False depending whether the catogory/seveirty
                could be extracted or not
        __metadata - dictionary with extracted metadata
    """
    logger = logging.getLogger(__name__)

    # Find all comment sections
    __match = re.findall(r"\<\!\-\-(?:.|\n|\r)*?-->", template_content)

    # Extract metadata from comment section
    for __entry in __match:
        # Remove comment delimiters
        __entry = re.sub(re.compile("^<!--\n*?"), "", __entry)
        __entry = re.sub(re.compile("-->\n*?$"), "", __entry)

        # Load remaining comment setion as YAML
        try:
            __metadata = yaml.load(__entry, Loader=yaml.BaseLoader)
            logger.debug(
                "Extracted the following metadata from template: %s" % template_file
            )
            logger.debug("Metadata: %s" % __metadata)
            return (True, __metadata)
        except ScannerError:
            logger.warning(
                "Unable to decode YAML metadata in file '%s', check if it has valid YAML syntax"
                % template_file
            )
        except ParserError:
            logger.warning(
                "Unable to decode YAML metadata in file '%s', check if it has valid YAML syntax"
                % template_file
            )

    logger.warning(
        "Extration of template metadata failed for template '%s' (likely due to metadata not present in template, safe to ignore)"
        % template_file
    )
    return (False, {})


def vetr_check_dataformat(vetr_data: dict):
    """
    Analyses the output of ACI vetR to identify wether it has
    the format of vetR 2.0.8 (or later), or an earlier version

    Input:
        vetr_data - dictionary containing vetR output (JSON loaded into dictionary)

    Output:
        vetR_version - String that indicates the vetR format (dataformat_2_0_0 or dataformat_2_0_8)
                       If dataformat_2_0_0 returned, then data must be converted
                       prior to proceeding with analysis
    """

    logger = logging.getLogger(__name__)
    logger.info("Verfifying dataformat of ACI vetR output")

    __vetr_2_0_0_keys = [
        "meta",
        "firmware",
        "admin",
        "fabricStats",
        "eol",
        "epLoopProtection",
        "rogueEPControl",
        "ipAging",
        "remoteEPlearning",
        "enforceSubnetCheck",
        "portTracking",
        "coopStrict",
        "bfdFabricInt",
        "domainValidation",
        "mcp",
        "dom",
        "multipod",
        "isisMetric",
        "tenantStats",
        "bdStats",
        "ingressPolicyEnforcement",
        "vzAny",
        "l3outRedundancy",
        "scale",
        "health",
        "ssd",
    ]
    __vetr_2_0_8_keys = [
        "meta",
        "stats",
        "apic",
        "system",
        "faults",
        "tenant",
        "health",
        "fabric",
        "access",
        "admin",
        "apps",
        "scale",
        "eol",
    ]

    # Check dictionary keys
    if len(vetr_data.keys()) == len(__vetr_2_0_8_keys):
        # Check that all expected keys exists
        for key in vetr_data.keys():
            if key not in __vetr_2_0_8_keys:
                logger.error(
                    "Dataformat of ACI vetR output seems to be broken. Non-expected vetR 2.0.8+ data key '{}' was found, exiting...".format(
                        key
                    )
                )
                exit(1)

        # Dataformat looks to be ok
        logger.info("Dataformat of ACI vetR output has expected structure")
        return "dataformat_2_0_8"
    elif len(vetr_data.keys()) == len(__vetr_2_0_0_keys):
        # Check that all expected keys exists
        for key in vetr_data.keys():
            if key not in __vetr_2_0_0_keys:
                logger.error(
                    "Dataformat of ACI vetR output seems to be broken. Non-expected vetR 2.0.0 data key '{}' was found, exiting...".format(
                        key
                    )
                )
                exit(1)

        logger.info(
            "Dataformat of ACI vetR output requires conversion as it has older structure (pre-2.0.8)"
        )
        return "dataformat_2_0_0"
    else:
        logger.error("Dataformat of ACI vetR output an not be identified, exiting...")
        exit(1)


def vetr_convert_dataformat(vetr_data: dict):
    """
    Converts the ACI vetR dataformat from version 2.0.0 to 2.0.8 format

    Input:
        vetr_data - dictionary containing vetR output (JSON loaded into dictionary)

    Output:
        __conversion_output - dictionary containing the converted vetR output
    """

    logger = logging.getLogger(__name__)
    logger.info("Converting vetR data struture")

    # Define key mappings between formats, using vetR 2.0.0 format as key and underscore as separator
    __conversion = dict()
    __conversion["meta"] = "meta"
    __conversion["firmware"] = "admin_firmwareVersion"
    __conversion["admin"] = dict()
    __conversion["admin"]["encryptedBackups"] = "system_encryptedBackups"
    __conversion["fabricStats"] = "stats_fabric"
    __conversion["eol"] = dict()
    __conversion["eol"]["apic"] = "eol_apic"
    __conversion["epLoopProtection"] = "system_epLoopProtection"
    __conversion["rogueEPControl"] = "system_rogueEPControl"
    __conversion["ipAging"] = "system_ipAging"
    __conversion["remoteEPlearning"] = "system_remoteEPlearning"
    __conversion["enforceSubnetCheck"] = "system_enforceSubnetCheck"
    __conversion["portTracking"] = "system_portTracking"
    __conversion["rogueEPControl"] = "system_rogueEPControl"
    __conversion["coopStrict"] = "fabric_coopStrict"
    __conversion["bfdFabricInt"] = "fabric_bfdFabricInt"
    __conversion["domainValidation"] = "system_domainValidation"
    __conversion["mcp"] = dict()
    __conversion["mcp"]["interface"] = "access_mcpInterface"
    __conversion["mcp"]["global"] = "fabric_mcpGlobal"
    __conversion["dom"] = "fabric_dom"
    __conversion["multipod"] = "stats_multipod"
    __conversion["isisMetric"] = "fabric_isisMetric"
    __conversion["tenantStats"] = "tenant_stats"
    __conversion["bdStats"] = "tenant_bdStats"
    __conversion["ingressPolicyEnforcement"] = "tenant_ingressPolicyEnforcement"
    __conversion["vzAny"] = "tenant_vzAny"
    __conversion["l3outRedundancy"] = "tenant_l3outRedundancy"
    __conversion["scale"] = dict()
    __conversion["scale"]["fabric"] = "scale_fabric"
    __conversion["scale"]["guide"] = "scale_guide"
    __conversion["scale"]["switch"] = "scale_switch"
    __conversion["health"] = "health"
    __conversion["ssd"] = "faults_ssd"

    __conversion_output = dict()
    for key in vetr_data.keys():
        try:
            logger.debug("Processing JSON key '{}'".format(key))
            # check if nested data is expected
            if type(__conversion[key]) == dict:
                logger.debug(
                    "\tContains nested data structures so initiating loop for children"
                )

                for child_key in vetr_data[key].keys():
                    logger.debug("\t\tProcessing Child JSON key '{}'".format(child_key))
                    try:
                        # verify that no additional nesting is expected
                        if type(__conversion[key][child_key]) is not str:
                            logger.fatal(
                                "An unsupported level of nested data was found while processing child key '{}', exiting...".format(
                                    child_key
                                )
                            )
                            exit(1)

                        # Converting data structures
                        logger.debug("\tContains data so converting to data structure")
                        base_mapping_result = __conversion[key][child_key]
                        mapping_elements = base_mapping_result.split("_")
                        if len(mapping_elements) == 1:
                            if mapping_elements[0] not in __conversion_output.keys():
                                __conversion_output[mapping_elements[0]] = vetr_data[
                                    key
                                ][child_key]
                            else:
                                logger.fatal(
                                    "Input data seems to have duplicated data for key '{}', exiting...".format(
                                        child_key
                                    )
                                )
                                exit(1)
                        elif len(mapping_elements) == 2:
                            if mapping_elements[0] not in __conversion_output.keys():
                                __conversion_output[mapping_elements[0]] = dict()

                            if (
                                mapping_elements[1]
                                not in __conversion_output[mapping_elements[0]].keys()
                            ):
                                __conversion_output[mapping_elements[0]][
                                    mapping_elements[1]
                                ] = vetr_data[key][child_key]
                            else:
                                logger.fatal(
                                    "Input data seems to have duplicated data for key '{}', exiting...".format(
                                        key
                                    )
                                )
                                exit(1)

                        else:
                            logger.fatal(
                                "An unsupported leel of nesting data was found in the during data convertsion, exiting..."
                            )
                            exit(1)

                    except KeyError:
                        logger.fatal(
                            "Found an unmapped child key '{}', exiting...".format(
                                child_key
                            )
                        )
                        exit(1)

            else:
                logger.debug("\tContains data so converting to data structure")
                base_mapping_result = __conversion[key]
                mapping_elements = base_mapping_result.split("_")
                if len(mapping_elements) == 1:
                    if mapping_elements[0] not in __conversion_output.keys():
                        __conversion_output[mapping_elements[0]] = vetr_data[key]
                    else:
                        logger.fatal(
                            "Input data seems to have duplicated data for key '{}', exiting...".format(
                                key
                            )
                        )
                        exit(1)
                elif len(mapping_elements) == 2:
                    if mapping_elements[0] not in __conversion_output.keys():
                        __conversion_output[mapping_elements[0]] = dict()

                    if (
                        mapping_elements[1]
                        not in __conversion_output[mapping_elements[0]].keys()
                    ):
                        __conversion_output[mapping_elements[0]][
                            mapping_elements[1]
                        ] = vetr_data[key]
                    else:
                        logger.fatal(
                            "Input data seems to have duplicated data for key '{}', exiting...".format(
                                key
                            )
                        )
                        exit(1)
                else:
                    logger.fatal(
                        "An unsupported leel of nesting data was found in the during data convertsion, exiting..."
                    )
                    exit(1)

        except KeyError:
            logger.fatal("Found an unmapped key '{}', exiting...".format(key))
            exit(1)

    # Return converted datastructure
    return __conversion_output


def vetr_analyse_output(vetr_data: dict):
    """
    Analyses the output of ACI vetR and extracts the recommended actions

    Input:
        vetr_data - dictionary containing vetR output (JSON loaded into dictionary)

    Output:
        __output - Dictionary with the recommended actions, key is the test type and value is the result from ACI vetR
    """
    logger = logging.getLogger(__name__)
    __output = {}

    # Test Prefix used to classify tests as comming from ACI vetR
    __test_prefix = "vetR_"

    logger.info("Analysing ACI vetR output")
    for __path, __entry in get_nested_dict_entries_containing_key(
        vetr_data, "actionRecommended"
    ):
        if __entry["actionRecommended"]:
            # Skip if vetR analysis has been marked as failed
            if "error" in __entry:
                logger.warning(
                    "Skipping vetR action '{}' as vetR analysis failed with message '{}'".format(
                        "_".join(__path), __entry["error"]
                    )
                )
                continue

            # Add recommended actions to ouput
            __entry_key = "_".join(__path)
            if __entry_key in __output:
                logger.critical(
                    "ACI vetR analysis failed, multiple '%s' recommendations found, exiting..."
                    % __entry_key
                )
                exit(1)
            else:
                # Ignore vetR BFD finding if recommendation is to enable BFD, as this is a bug fixed in vetR 2.1.11 and later
                # More information: https://techzone.cisco.com/t5/Application-Centric/Best-Practices-Global-Settings-you-should-do-by-default-on-day-0/ta-p/1260430%20item%20#10
                if (
                    __entry_key == "fabric_bfdFabricInt"
                    and __entry["recommended"]["enabled"] is True
                ):
                    logger.debug(
                        "Skipping action 'fabric_bfdFabricInt' as it has an incorrect recommended state. Known bug in vetR prior to 2.1.11"
                    )
                    continue

                # Add recommended action to dictionary
                __output[__test_prefix + __entry_key] = __entry

    logger.info("Found %s ACI vetR recommended actions" % len(__output))
    return __output


def vetr_render_actions(template_path: str, vetr_actions: dict, ignore_list: dict):
    """
    Renders document templates for the ACI vetR findings

    Input:
        template path - Path to the template folder
        vetr_actions - Dictionary containing the vetR findings (output of the vetr_analyse_output function)
        ignore_list - Dictionary containing the list of findings to be ignored

    Output:
        __rendered_output - Dictionary with the document sniplets for each vetR finding
    """

    logger = logging.getLogger(__name__)
    logger.info("Rendering ACI vetR actions")
    __rendered_output = {}
    __audit_template = TemplateRender(template_path)
    for __action in vetr_actions:
        # Massage event name to separate tool name from event name
        __action_components = __action.split("_")
        __action_name = "_".join(__action_components[1:])

        # Check if action should be ignored
        if __action in ignore_list["vetR"]:
            logger.debug(
                "SKIPPING Rendering of verR action '%s' as per the ignore list"
                % __action_name
            )
            continue

        # define template filename and prepare data structure for rendered action
        __template_file = __action + ".md"
        __rendered_output[__action] = dict()

        # Render template
        (
            __success,
            __rendered_template_output,
        ) = __audit_template.render_template(__template_file, vetr_actions[__action])

        if __success:
            __rendered_output[__action]["content"] = __rendered_template_output
            # Extract event metadata from successfully rendered templates
            if __rendered_output[__action]["content"] is not None:
                __success, __metadata = get_template_metadata(
                    __rendered_output[__action]["content"], __template_file
                )
                if __success:
                    __rendered_output[__action]["metadata"] = __metadata
                else:
                    __rendered_output[__action]["metadata"] = None
                    __rendered_output[__action][
                        "error"
                    ] = "Template metadata extraction failed"
        else:
            # Template rendering failed
            # Add error message to internal data structure
            __rendered_output[__action]["content"] = None
            __rendered_output[__action]["metadata"] = None
            __rendered_output[__action]["error"] = __rendered_template_output

    return __rendered_output


class nae_session(object):
    """
    Class used for all interactions with NAE in order to extract smart events for a given assurance group
    """

    def __init__(self, protocol: str, hostname: str, username: str, password: str, version: str):
        if protocol.lower() == "http" or protocol.lower() == "https":
            self.base_url = protocol.lower() + "://" + hostname.lower()
        else:
            raise ValueError("Supported protocols are http and https")
        self.username = username
        self.password = password
        self.version = version
        self.authentication_header = {}
        self.timeout = 180

    def handle_request(self, url, reqType, data):
        logger = logging.getLogger(__name__)
        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return (False, "")

        try:
            if reqType == "post":
                __req = requests.post(
                    url=url,
                    headers=self.authentication_header,
                    data=data,
                    verify=False,
                    timeout=self.timeout,
                )
            elif reqType == "put":
                __req = requests.put(
                    url=url,
                    headers=self.authentication_header,
                    data=data,
                    verify=False,
                    timeout=self.timeout,
                )
            elif reqType == "delete":
                __req = requests.delete(
                    url=url,
                    headers=self.authentication_header,
                    data=data,
                    verify=False,
                    timeout=self.timeout,
                )
            elif reqType == "get":
                __req = requests.get(
                    url=url,
                    headers=self.authentication_header,
                    verify=False,
                    timeout=self.timeout,
                )
        except requests.exceptions.Timeout:
            logger.error(
                "Connection timeout towards NAE '{}', exiting...".format(self.base_url)
            )
            exit(1)
        except requests.exceptions.ConnectionError:
            logger.error(
                "Connection error towards NAE '{}', exiting...".format(self.base_url)
            )
            exit(1)
        except requests.exceptions.InvalidURL:
            logger.error("Invalid URL used toawards NAE '{}', exiting...".format(url))
            exit(1)

        if (
            __req.status_code == 200
            or __req.status_code == 201
            or __req.status_code == 202
        ):
            try:
                __response = __req.json()
                return __response
            except:
                return True
        elif self.version == "ndi" and __req.status_code == 404:
            # Handle that NDI returns status_code 404 with a payload indicating success or failure
            try:
                __response = __req.json()
                logger.debug(f"Received status code '{__req.status_code}' from NDI")
                logger.debug(f"Received response text '{__req.text}' from NDI")
                return __response
            except:
                logger.error(
                    "Received status code '{}', exiting...".format(__req.status_code)
                )
                logger.debug(
                    "Received response text '{}', exiting...".format(__req.text)
                )
                exit(1)
        elif self.version == "ndi" and __req.status_code == 400:
            # Handle that NDI returns status_code 400 when aggregated smart event details are missing
            try:
                __response = __req.json()
                if __response["Message"].startswith("Data is not displayed for the given time range start time"):
                    logger.debug(f"Received status code '{__req.status_code}' from NDI")
                    logger.debug(f"Received response text '{__req.text}' from NDI")
                    return(False)
            except:
                logger.error(
                    "Received status code '{}', exiting...".format(__req.status_code)
                )
                logger.debug(
                    "Received response text '{}', exiting...".format(__req.text)
                )
                exit(1)
        else:
            logger.error(
                "Received status code '{}', exiting...".format(__req.status_code)
            )
            logger.debug(
                "Received response text '{}', exiting...".format(__req.text)
            )
            exit(1)

    def login(self):
        """
        Logon to NAE
            :parameter:
                nae_ip (__required): IP address of Cisco NAE instance to connect to
                nae_user (__required): User name to log on to device specified by nae_ip
                nae_pass (__required): Password for nae_user
        """
        logger = logging.getLogger(__name__)
        if self.version == "ndi":
            logger.info("Establishing NDI login session")
        else:
            logger.info("Establishing NAE login session")

        __data = dict()
        __data["username"] = self.username
        __data["password"] = self.password
        __data = json.dumps(__data)

        __header = dict()
        __header["Content-Type"] = "application/json"
        __header["Accept"] = "application/json"

        # NAE Login
        if self.version == "nae":
            """
                Executes whoami __request first to get the one time password and retireves session id, which will be used to login and
                get the actual token and session id that will be used in all subsequent REST Call.
                URL - "https://nae_ip/api/v1/whoami"
            """
            __url = self.base_url + "/nae/api/v1/whoami"
            try:
                __req = requests.get(
                    url=__url, headers=__header, verify=False, timeout=self.timeout
                )
            except requests.exceptions.Timeout:
                logger.error(
                    "Connection timeout towards NAE '{}', exiting...".format(self.base_url)
                )
                exit(1)
            except requests.exceptions.ConnectionError:
                logger.error(
                    "Connection error towards NAE '{}', exiting...".format(self.base_url)
                )
                exit(1)
            except requests.exceptions.InvalidURL:
                logger.error("Invalid URL used toawards NAE '{}', exiting...".format(__url))

            if __req.status_code == 200 or __req.status_code == 201:
                __otp = __req.headers["X-NAE-LOGIN-OTP"]
                __sid = __req.headers["Set-Cookie"]
                __sid = str(__sid).split(";")[0]

                """
                    Taking one time password and session id as inputs, this generates a token after authenticating
                    (Username and Password sent in the body).
                    URL - URL - "https://nae_ip/api/v1/login"
                """
                __header["X-NAE-LOGIN-OTP"] = __otp
                __header["Cookie"] = __sid
                __url = self.base_url + "/nae/api/v1/login"
                try:
                    __req = requests.post(
                        url=__url,
                        data=__data,
                        headers=__header,
                        verify=False,
                        timeout=self.timeout,
                    )
                except requests.exceptions.Timeout:
                    logger.error(
                        "Connection timeout towards NAE '{}', exiting...".format(
                            self.base_url
                        )
                    )
                    exit(1)
                except requests.exceptions.ConnectionError:
                    logger.error(
                        "Connection error towards NAE '{}', exiting...".format(
                            self.base_url
                        )
                    )
                    exit(1)
                except requests.exceptions.InvalidURL:
                    logger.error(
                        "Invalid URL used toawards NAE '{}', exiting...".format(__url)
                    )

                if __req.status_code == 200 or __req.status_code == 201:
                    __nae_header = {}
                    __nae_token = __req.headers["X-NAE-CSRF-TOKEN"]
                    __cookie = __req.headers["Set-Cookie"]
                    __nae_session = str(__cookie).split(";")[0]

                    __nae_header["Content-Type"] = "application/json"
                    __nae_header["Accept"] = "application/json"
                    __nae_header["X-NAE-CSRF-TOKEN"] = __nae_token
                    __nae_header["Cookie"] = __nae_session

                    logger.debug("NaE Login successful")
                    self.authentication_header = __nae_header
                    return True
                else:
                    logger.error("NAE Login Failed")
                    return False

        # Nexus Dashboard Login
        elif self.version == "ndi":
            __url = self.base_url + "/login"
            try:
                __req = requests.post(
                    url=__url,
                    data=__data,
                    headers=__header,
                    verify=False,
                    timeout=self.timeout,
                )
            except requests.exceptions.Timeout:
                logger.error(
                    "Connection timeout towards NDI '{}', exiting...".format(
                        self.base_url
                    )
                )
                exit(1)
            except requests.exceptions.ConnectionError:
                logger.error(
                    "Connection error towards NDI '{}', exiting...".format(
                        self.base_url
                    )
                )
                exit(1)
            except requests.exceptions.InvalidURL:
                logger.error(
                    "Invalid URL used toawards NDI '{}', exiting...".format(__url)
                )

            if __req.status_code == 200 or __req.status_code == 201:
                __nae_header = {}
                __cookie = __req.headers["Set-Cookie"]
                __nae_session = str(__cookie).split(";")[0]

                __nae_header["Content-Type"] = "application/json"
                __nae_header["Accept"] = "application/json"
                __nae_header["Cookie"] = __nae_session

                logger.debug("NDI Login successful")
                self.authentication_header = __nae_header
                return True
            else:
                logger.error("NDI Login Failed")
                return False


    def read_in_chunks(self, file_object, chunk_size):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def nae_upload_file_chunk(self, filename, file_upload_id, filesize):
        logger = logging.getLogger(__name__)

        if self.version == "nae":
            logger.info("Upload NAE file chunk '%s'" % filename)
            __url = (
                self.base_url
                + "/nae/api/v1/file-services/upload-file/"
                + file_upload_id
                + "/chunk"
            )
            # __url = self.base_url + "/nae/api/v1/file-services/upload-file/" + file_upload_id

            content_size = os.stat(filename).st_size
            defined_chunk_size = 10000000

            amount_of_chunks = float(content_size) / float(defined_chunk_size)
            # print(amount_of_chunks)
            amount_of_chunks = int(math.ceil(amount_of_chunks))
            # print(amount_of_chunks)

            session = requests.Session()
            with open(filename, "rb") as f:

                index = 0
                offset = 0

                for chunk in self.read_in_chunks(f, defined_chunk_size):

                    chunksize = len(chunk)

                    logging.info(f"Index {index} offset {offset} chunksize {chunksize}")

                    chunk_info = {
                        "chunk_id": index,
                        "size_in_bytes": chunksize,
                        "offset": offset,
                    }
                    chunk_info = json.dumps(chunk_info)
                    # print(chunk_info)

                    m = MultipartEncoder(
                        fields={
                            "qqpartindex": str(index),
                            "qqpartbyteoffset": str(offset),
                            "qqchunksize": str(chunksize),
                            "qqtotalparts": str(amount_of_chunks),
                            "qqtotalfilesize": str(content_size),
                            "qqfilename": filename,
                            "qquuid": file_upload_id,
                            "chunk-info": ("blob", chunk_info, "application/json"),
                            "chunk-data": ("blob", chunk, "application/octet-stream"),
                        }
                    )

                    headers = dict(self.authentication_header)
                    headers["Prefer"] = "respond-async"
                    headers["Content-Type"] = m.content_type
                    headers["Accept"] = "application/json"
                    headers["Accept-Encoding"] = "gzip, deflate, br"
                    # print(headers)

                    try:
                        result = session.post(__url, headers=headers, data=m, verify=False)
                        # print(result)
                        # print(result.text)
                    except session.exceptions.RequestException as err:
                        logger.error("Oops: Something Else", err)

                    # prep next loop
                    index += 1
                    offset += chunksize

                # result = self.handle_request(__url, 'post', json.dumps(data))
                return True

        elif self.version == "ndi":
            logger.info("Upload NDI file chunk '%s'" % filename)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/uploadFile/"
                + file_upload_id
                + "/chunk"
            )

            content_size = os.stat(filename).st_size
            defined_chunk_size = 10000000

            amount_of_chunks = float(content_size) / float(defined_chunk_size)
            # print(amount_of_chunks)
            amount_of_chunks = int(math.ceil(amount_of_chunks))
            # print(amount_of_chunks)

            session = requests.Session()
            with open(filename, "rb") as f:

                index = 0
                offset = 0

                for chunk in self.read_in_chunks(f, defined_chunk_size):

                    chunksize = len(chunk)

                    logging.info(f"Index {index} offset {offset} chunksize {chunksize}")

                    chunk_info = {
                        "chunkId": index,
                        "sizeInBytes": chunksize,
                        "offset": offset,
                    }
                    chunk_info = json.dumps(chunk_info)
                    # print(chunk_info)

                    m = MultipartEncoder(
                        fields={
                            "qqpartindex": str(index),
                            "qqpartbyteoffset": str(offset),
                            "qqchunksize": str(chunksize),
                            "qqtotalparts": str(amount_of_chunks),
                            "qqtotalfilesize": str(content_size),
                            "qqfilename": filename,
                            "qquuid": file_upload_id,
                            "chunkInfo": ("blob", chunk_info, "application/json"),
                            "chunkData": ("blob", chunk, "application/octet-stream"),
                        }
                    )

                    headers = dict(self.authentication_header)
                    headers["Prefer"] = "respond-async"
                    headers["Content-Type"] = m.content_type
                    headers["Accept"] = "application/json"
                    headers["Accept-Encoding"] = "gzip, deflate, br"
                    # print(headers)

                    try:
                        result = session.post(__url, headers=headers, data=m, verify=False)
                        # print(result)
                        # print(result.text)
                    except session.exceptions.RequestException as err:
                        logger.error("Oops: Something Else", err)

                    # prep next loop
                    index += 1
                    offset += chunksize

                # result = self.handle_request(__url, 'post', json.dumps(data))
                return True

    def nae_upload_file_complete(self, file_upload_id):
        logger = logging.getLogger(__name__)
        if self.version == "nae":
            logger.info("Post NAE file upload complete '%s'" % file_upload_id)
            __url = (
                self.base_url
                + "/nae/api/v1/file-services/upload-file/"
                + file_upload_id
                + "/complete"
            )

            data = {}

            result = self.handle_request(__url, "post", json.dumps(data))
            return result
        elif self.version == "ndi":
            logger.info("Post NDI file upload complete '%s'" % file_upload_id)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/uploadFile/"
                + file_upload_id
                + "/complete"
            )

            data = {}

            result = self.handle_request(__url, "post", json.dumps(data))
            return result

    def nae_analysis(self, ag_id, offline_analysis_id):
        logger = logging.getLogger(__name__)

        if self.version == "nae":
            logger.info("Create NAE analysis '%s'" % offline_analysis_id)
            __url = self.base_url + "/nae/api/v1/config-services/analysis"

            data = {
                "assurance_group_list": [{"uuid": ag_id}],
                "interval": 300,
                "iterations": 1,
                "offline_analysis_list": [{"uuid": offline_analysis_id}],
                "type": "OFFLINE",
            }

            result = self.handle_request(__url, "post", json.dumps(data))
            return result
        elif self.version == "ndi":
            logger.info("Create NDI analysis '%s'" % offline_analysis_id)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup/"
                + ag_id
                + "/fabric/"
                + offline_analysis_id
                + "/runOnlineAnalysis"
            )

            data = {}

            result = self.handle_request(__url, "post", json.dumps(data))
            return result


    def nae_offline_analysis(self, analysis_name, ag_id, file_upload_id):
        logger = logging.getLogger(__name__)

        if self.version == "nae":
            logger.info("Create NAE offline analysis '%s'" % analysis_name)
            __url = self.base_url + "/nae/api/v1/config-services/offline-analysis"

            data = {
                "aci_fabric_uuid": ag_id,
                "analysis_timeout_in_secs": "36000",
                "file_upload_uuid": file_upload_id,
                "unique_name": analysis_name,
            }

            result = self.handle_request(__url, "post", json.dumps(data))
            return result
        elif self.version == "ndi":
            logger.info("Create NDI offline analysis '%s'" % ag_id)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup/"
                + analysis_name
                + "/fabric/"
                + ag_id
                + "/runOfflineAnalysis"
            )

            data = {}

            result = self.handle_request(__url, "post", json.dumps(data))
            return result

    def nae_create_upload_file(self, filename, unique_name, filesize, ag_uuid = ""):
        logger = logging.getLogger(__name__)

        if self.version == "nae":
            logger.info("Create NAE upload_file '%s'" % unique_name)
            __url = self.base_url + "/nae/api/v1/file-services/upload-file"

            data = {
                "comment": "",
                "filename": filename,
                "size_in_bytes": filesize,
                "unique_name": unique_name,
                "upload_type": "OFFLINE_ANALYSIS",
            }

            result = self.handle_request(__url, "post", json.dumps(data))
            return result

        elif self.version == "ndi":
            logger.info("Create NDI upload_file '%s'" % unique_name)
            __url = self.base_url + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/uploadFile"

            data = {
                "comment": "",
                "filename": filename,
                "sizeInBytes": filesize,
                "uniqueName": unique_name,
                "uploadType": "OFFLINE_ANALYSIS",
                "insightGroupUuid": ag_uuid,
            }

            result = self.handle_request(__url, "post", json.dumps(data))
            return result

    def nae_return_uid_on_display_name(self, data, display_name):
        if self.version == "nae":
            for entry in data["value"]["data"]:
                if entry["display_name"] == display_name:
                    return entry["uuid"]

            return False
        elif self.version == "ndi":
            for entry in data["value"]["data"]:
                if entry["name"] == display_name:
                    return entry["uuid"]

            return False

    def nae_delete_assurance_group_by_name(self, ag_name):
        logger = logging.getLogger(__name__)

        if self.version == "ndi":
            logger.info("Searching NDI AG '%s'" % ag_name)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup/"
                + ag_name
            )
            data = {}
            result = self.handle_request(__url, "get", json.dumps(data))

            if result["success"]:
                result = self.nae_delete_assurance_group(ag_name)
                return(result)
            else:
                logger.info("No AG found")
                return True

        else:
            logger.info("Searching NAE AG '%s'" % ag_name)
            __url = self.base_url + "/nae/api/v1/config-services/assurance-group/fabric"
            data = {}
            result = self.handle_request(__url, "get", json.dumps(data))

            ag_id = self.nae_return_uid_on_display_name(result, ag_name)

            if ag_id:
                result = self.nae_delete_assurance_group(ag_id)
                return result
            else:
                logger.info("No AG found")
                return True

    def nae_monitor_analysis(self, unique_name, jobname = ""):
        logger = logging.getLogger(__name__)

        if self.version == "nae":
            logger.info("Searching NAE upload filename '%s'" % unique_name)

            __url = self.base_url + "/nae/api/v1/config-services/offline-analysis"
            data = {}
            while True:
                result = self.handle_request(__url, "get", json.dumps(data))

                found = False

                for entry in result["value"]["data"]:
                    if entry["unique_name"] == unique_name:
                        found = True
                        status = entry["status"]

                if not found:
                    logger.error("Analysis not found")

                if status == "ANALYSIS_NOT_STARTED":
                    logger.info("Current status '%s'" % status)
                elif status == "ANALYSIS_IN_PROGRESS":
                    logger.info("Current status '%s'" % status)
                elif status == "ANALYSIS_COMPLETED":
                    logger.info("Current status '%s'" % status)
                    break
                else:
                    logger.error("Unexpected status, bailing out '%s'" % status)
                    exit(1)

                time.sleep(10)

            return True
        elif self.version == "ndi":
            logger.info("Searching NDI offline analysis for '%s'" % unique_name)

            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/jobs/summary.json?count=10000&jobType=OFFLINE-ANALYSIS%2C%20OFFLINE-ANALYSIS-V6&insightsGroupName="
                + unique_name
            )
            data = {}

            # Wait upto 1 min (6x10s) for the offline analysis to be present
            __max_retry_count = 6
            __retry_count = 0

            while True:
                result = self.handle_request(__url, "get", json.dumps(data))

                found = False

                for entry in result["entries"]:
                    if entry["jobId"] == jobname:
                        found = True
                        status = entry["operSt"]


                if not found:
                    if __retry_count < __max_retry_count:
                        logger.info("Analysis not found, retrying")
                        time.sleep(10)
                        continue
                    else:
                        logger.error("Analysis not found, exiting")
                        exit(1)

                if status == "QUEUED":
                    logger.info("Current status '%s'" % status)
                elif status == "SCHEDULED":
                    logger.info("Current status '%s'" % status)
                elif status == "RUNNING":
                    logger.info("Current status '%s'" % status)
                elif status == "COMPLETE":
                    logger.info("Current status '%s'" % status)
                    break
                else:
                    logger.error("Unexpected status, bailing out '%s'" % status)
                    exit(1)

                time.sleep(10)

            return True

    def nae_delete_upload_file_by_name(self, filename):
        logger = logging.getLogger(__name__)
        logger.info("Searching upload filename '%s'" % filename)

        if self.version == "nae":
            __url = self.base_url + "/nae/api/v1/file-services/upload-file"
            data = {}
            result = self.handle_request(__url, "get", json.dumps(data))

            file_upload_id = self.nae_return_uid_on_display_name(result, filename)

            if file_upload_id:
                result = self.nae_delete_upload_file(file_upload_id)
                return result
            else:
                logger.info("No upload file found")
                return True

        elif self.version == "ndi":
            __url = self.base_url + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/uploadFile"
            data = {}
            result = self.handle_request(__url, "get", json.dumps(data))

            found = False
            for entry in result["value"]["data"]:
                if entry["filename"] == filename:
                    found = True
                    file_upload_id = entry["uuid"]

            if found:
                result = self.nae_delete_upload_file(file_upload_id)
                return result
            else:
                logger.info("No upload file found")
                return True

    def nae_delete_upload_file(self, file_upload_id):

        logger = logging.getLogger(__name__)
        logger.info("Deleting Upload file '%s'" % file_upload_id)

        if self.version == "nae":
            __url = (
                self.base_url + "/nae/api/v1/file-services/upload-file/" + file_upload_id
            )

            data = {}

            result = self.handle_request(__url, "delete", json.dumps(data))
            return result

        elif self.version == "ndi":
            __url = (
                self.base_url + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/uploadFile/" + file_upload_id
            )

            data = {}

            result = self.handle_request(__url, "delete", json.dumps(data))
            return result

    def nae_delete_assurance_group(self, assuance_group_id):

        logger = logging.getLogger(__name__)
        if self.version == "ndi":
            logger.info("Deleting NDI Assurance group '%s'" % assuance_group_id)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup/"
                + assuance_group_id
            )

            data = {
                "igName": assuance_group_id
            }

            result = self.handle_request(__url, "delete", json.dumps(data))
            return result
        else:
            logger.info("Deleting NAE Assurance group '%s'" % assuance_group_id)
            __url = (
                self.base_url
                + "/nae/api/v1/config-services/assurance-group/fabric/"
                + assuance_group_id
            )

            data = {}

            result = self.handle_request(__url, "delete", json.dumps(data))
            return result

    def nae_rename_assurance_group(self, assuance_group_id, ag_name_finished):

        logger = logging.getLogger(__name__)

        if self.version == "nae":
            logger.info("Renaming Assurance group '%s'" % assuance_group_id)

            logger.info("Searching AG '%s'" % assuance_group_id)
            __url = (
                self.base_url
                + "/nae/api/v1/config-services/assurance-group/fabric/"
                + assuance_group_id
            )
            data = {}
            result = self.handle_request(__url, "get", json.dumps(data))
            logger.info("Searching AG '%s' - received response" % assuance_group_id)
            if result and "value" in result and "data" in result["value"]:
                payload = {}
                payload = result["value"]["data"]
                payload["unique_name"] = ag_name_finished
                payload["description"] = "Blowtorch processing finished"
                payload.pop("display_name")
                payload.pop("interval")

                logger.info("Renaming AG '%s'" % assuance_group_id)
                __url = (
                    self.base_url
                    + "/nae/api/v1/config-services/assurance-group/fabric/"
                    + assuance_group_id
                )
                data = payload

                result = self.handle_request(__url, "put", json.dumps(data))
                return result
            else:
                return None

        elif self.version == "ndi":
            logger.info("Renaming Assurance group '%s'" % assuance_group_id)
            logger.info("Searching NDI AG '%s'" % assuance_group_id)
            __url = (
                self.base_url
                + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup/"
                + assuance_group_id
            )
            data = {}
            result = self.handle_request(__url, "get", json.dumps(data))
            if result and "value" in result and "data" in result["value"]:
                payload = {}
                payload = result["value"]["data"][0]
                payload["name"] = ag_name_finished
                payload["description"] = "Blowtorch processing finished"
                payload.pop("assuranceEntities")
                payload.pop("links")
                # print(payload)

                logger.info("Renaming AG '%s'" % assuance_group_id)
                __url = (
                    self.base_url
                    + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup/"
                    + assuance_group_id
                )
                data = payload

                result = self.handle_request(__url, "put", json.dumps(data))
                print(result)
                return result
            else:
                return None



    def nae_create_assurance_group(self, assuance_group: str):

        logger = logging.getLogger(__name__)
        if self.version == "ndi":
            logger.info("Creating NDI Site group")
            __url = self.base_url + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/config/insightsGroup"

            data = {
                "name": assuance_group,
                "description": assuance_group,
                "type": "OFFLINE"
            }
            result = self.handle_request(__url, "post", json.dumps(data))
            return result

        else:
            logger.info("Creating NAE Assurance group '%s'" % assuance_group)
            __url = self.base_url + "/nae/api/v1/config-services/assurance-group/fabric"

            data = {
                "active": True,
                "analysis_id": "",
                "analysis_schedule_id": "",
                "analysis_timeout_in_secs": 36000,
                "apic_configuration_export_policy": {
                    "apic_configuration_export_policy_enabled": False
                },
                "application_id": "",
                "associated_fabric_uuids": None,
                "assured_fabric_type": "ACI_FABRIC",
                "assured_network_type": "ACI_FABRIC",
                "description": assuance_group,
                "operational_mode": "OFFLINE",
                "status": "STOPPED",
                "unique_name": assuance_group,
            }

            result = self.handle_request(__url, "post", json.dumps(data))
            return result

    def nae_get_fabric_id_all(self):
        """
        Estracts all fabric ids
        returns dictionary with fabric IDs. Key is the assurance group name, value is the fabric id
        """

        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return (False, "")

        logger = logging.getLogger(__name__)
        logger.info("Getting all NAE Fabric IDs ")
        fabricId = {}
        __url = self.base_url + "/nae/api/v1/config-services/assurance-group/fabric"

        __response = self.handle_request(__url, "get", "")
        if __response:
            for entry in __response["value"]["data"]:
                fabricId[entry["display_name"]] = entry["uuid"]
            return (True, fabricId)
        else:
            logger.error(
                "A failure occured while retrieving NAE Fabric ID for assurance group '%s'"
                % assuance_group
            )
            return (False, "")

    def nae_get_fabric_id_by_assurance_group(self, assuance_group: str):
        """
        Estracts the fabric id for the specified assurance group
        """

        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return (False, "")

        logger = logging.getLogger(__name__)
        logger.info("Getting NAE Fabric ID for assurance group '%s'" % assuance_group)
        __url = self.base_url + "/nae/api/v1/config-services/assurance-group/fabric"

        __response = self.handle_request(__url, "get", "")
        if __response:
            for entry in __response["value"]["data"]:
                if entry["display_name"] == assuance_group:
                    logger.debug("Found assurance group entry: %s" % entry)
                    return (True, entry["uuid"])

            # Did not find the requested assurance group
            logger.error(
                "Unable to locate assurance group with a display_name of '%s'"
                % assuance_group
            )
            return (False, "")
        else:
            logger.error(
                "A failure occured while retrieving NAE Fabric ID for assurance group '%s'"
                % assuance_group
            )
            return (False, "")

    def nae_get_epoch_id_by_fabric_id(self, fabricId: str):
        """
        Extracts the last epoch id for the specified fabric id
        """

        logger = logging.getLogger(__name__)
        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return False

        logger.info("Getting NAE ephoch (last) for fabric id %s" % fabricId)
        __url = (
            self.base_url
            + "/nae/api/v1/event-services/epochs?$fabric_id="
            + fabricId
            + "&$size=1"
        )
        __response = self.handle_request(__url, "get", "")

        if __response:
            logger.debug("Found epoch entry: %s" % __response)
            if len(__response["value"]["data"]) == 0:
                logger.warning("No epoc data found for fabric id '%s'" % fabricId)
                return (False, "")
            else:
                return (True, __response["value"]["data"][0]["epoch_id"])
        else:
            logger.error(
                "A failure occured while retrieving NAE epoch id for fabric id '%s'"
                % fabricId
            )
            return (False, "")

    def nae_get_smart_events_by_epoch_id_and_page(self, epochId: str, pageId: int):
        """
        Retrieves all smarts events belonging to a ephoch on a per page basis.

        Returns the raw API response in JSON format
        """

        logger = logging.getLogger(__name__)
        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return (False, "")

        logger.debug(
            "Getting NAE smart events for epoch id {} (page {})".format(epochId, pageId)
        )
        __url = (
            self.base_url
            + "/nae/api/v1/event-services/smart-events?$epoch_id="
            + epochId
            + "&$page="
            + str(pageId)
            + "&$size=200"
        )
        __response = self.handle_request(__url, "get", "")
        if __response:
            return (True, __response)
        else:
            logger.error(
                "A failure occured while retrieving NAE smart events for epoch id '{}' and page {}".format(
                    epochId, pageId
                )
            )
            return (False, "")

    def nae_get_smart_events_by_epoch_id(self, epochId: str):
        """
        Estracts the smart events for the specified epoch id

        Returns a dictionary with the smart events
        """

        logger = logging.getLogger(__name__)
        logger.info("Getting NAE smart events for epoch id %s" % epochId)
        __output = {}

        # Test Prefix used to classify tests as comming from ACI vetR
        __test_prefix = "nae_"

        __success, __response = self.nae_get_smart_events_by_epoch_id_and_page(
            epochId, 0
        )
        if __success:
            __total_page_count = __response["value"]["data_summary"]["total_page_count"]
            logger.info(
                "There are {} pages of smart events in total (zero indexed)".format(
                    __total_page_count
                )
            )
            logger.debug("Found {} smart event entries on page 0".format(__response))

            # Iterate through the smart events
            for __event in __response["value"]["data"]:
                __event_name = __test_prefix + __event["smart_event_info"]["name"]

                # Build nested dictionary structure if not already in place
                if __event_name not in __output.keys():
                    __output[__event_name] = {}
                if "event_list" not in __output[__event_name].keys():
                    __output[__event_name]["event_list"] = []
                if "severity" not in __output[__event_name].keys():
                    __output[__event_name]["severity"] = ""

                # Add smart event details to output dictionary
                __output[__event_name]["description"] = __event["description"]
                __output[__event_name]["severity"] = __event["severity"]["name"]
                __output[__event_name]["event_list"].append(
                    __event["additional_details"]
                )

        else:
            logger.error(
                "A failure occured while retrieving NAE smart events for epoch id '%s' page 0"
            )
            return (False, "")

        # Request additional pages of smart events if they exist
        if __total_page_count > 1:
            __current_page_count = 1
            while __current_page_count < __total_page_count:
                logger.info(
                    "Retrieving page {} of smart events".format(__current_page_count)
                )
                __success, __response = self.nae_get_smart_events_by_epoch_id_and_page(
                    epochId, __current_page_count
                )

                if __success:
                    logger.debug(
                        "Found {} smart event entris on page {}".format(
                            __response, __current_page_count
                        )
                    )

                    # Iterate through the smart events
                    for __event in __response["value"]["data"]:
                        __event_name = (
                            __test_prefix + __event["smart_event_info"]["name"]
                        )

                        # Build nested dictionary structure if not already in place
                        if __event_name not in __output.keys():
                            __output[__event_name] = {}
                        if "event_list" not in __output[__event_name].keys():
                            __output[__event_name]["event_list"] = []
                        if "severity" not in __output[__event_name].keys():
                            __output[__event_name]["severity"] = ""
                        if "data_source" not in __output[__event_name].keys():
                            __output[__event_name]["data_source"] = ""

                        # Add smart event details to output dictionary
                        __output[__event_name]["description"] = __event["description"]
                        __output[__event_name]["severity"] = __event["severity"]["name"]
                        __output[__event_name]["event_list"].append(
                            __event["additional_details"]
                        )
                        __output[__event_name]["data_source"] = "nae"

                    # Increment current page count
                    __current_page_count = __current_page_count + 1

                else:
                    logger.error(
                        "A failure occured while retrieving NAE smart events for epoch id '%s' page {}".format(
                            __current_page_count
                        )
                    )
                    return (False, "")

        # Return smart events
        return (True, __output)

    def ndi_get_fabric_name_by_assurance_group(self, assuance_group: str):
        """
        Estracts the fabric id for the specified assurance group
        """

        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return (False, "")

        logger = logging.getLogger(__name__)
        logger.info("Getting NDI Fabric ID for assurance group '%s'" % assuance_group)
        __url = self.base_url + "/sedgeapi/v1/cisco-nir/api/api/telemetry/fabrics.json?insightsGroupName=%s" % assuance_group

        __response = self.handle_request(__url, "get", "")
        if __response:
            # Expecting to only find a single fabric under the assurance group
            if __response["totalItemsCount"] == 1:
                logger.debug("Found assurance group entry: %s" % __response)
                return (True, __response["entries"][0]["fabricName"])
            else:
                # Did not find the requested assurance group
                logger.debug("Did not find a assurance group entry, received: %s" % __response)
                logger.error(
                    "Unable to locate assurance group with a display_name of '%s'"
                    % assuance_group
                )
                return (False, "")
        else:
            logger.error(
                "A failure occured while retrieving NAE Fabric ID for assurance group '%s'"
                % assuance_group
            )
            return (False, "")

    def ndi_get_smart_events_summary_by_assurance_group_and_offset(self, assurance_group: str, start_time: str, end_time: str, count: int, offset: int):
        logger = logging.getLogger(__name__)

        # Query smart events
        __url = (
            self.base_url
            + "/sedgeapi/v1/cisco-nir/api/api/telemetry/anomalies/details.json?aggr=mnemonicTitle&insightsGroupName="
            + assurance_group
            + "&startTs="
            + start_time
            + "&endTs="
            + end_time
            + "&count="
            + str(count)
            + "&offset="
            + str(offset)
        )
        __response = self.handle_request(__url, "get", "")
        if __response:
            return (True, __response)
        else:
            logger.error(
                "A failure occured while retrieving NDI smart event summary for assurance group '{}' and offset {}".format(
                    assurance_group, offset
                )
            )
            return (False, "")

    def ndi_get_smart_event_details_by_fabric_name_and_offset(self, assurance_group: str, fabric_name: str, event_name: str, start_time: str, end_time: str, count: int, offset: int):
        logger = logging.getLogger(__name__)

        # Reformat start/end time to match API call
        start_time = start_time + "T00%3A00%3A00%2B00%3A00"
        end_time = end_time + "T23%3A59%3A59%2B00%3A00"

        __url = (
            self.base_url
            + "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/insightsGroup/"
            + assurance_group
            + "/anomalies/aggregateAffectedObjects.json?count="
            + str(count)
            + "&endTs="
            + end_time
            + "&fabricName="
            + fabric_name
            + "&mnemonicTitle="
            + event_name
            + "&offset="
            + str(offset)
            + "&startTs="
            + start_time
        )
        __response = self.handle_request(__url, "get", "")
        if __response:
            return (True, __response)
        else:
            logger.warning(
                "A failure occured while retrieving NDI smart event detail for assurance group '{}', smart event '{}' and offset {}".format(
                    assurance_group,
                    event_name,
                    offset
                )
            )
            return (False, "")

    def ndi_get_smart_events_by_fabric_name(self, assurance_group: str, fabric_name: str):
        """
        Estracts the smart events for the specified site group

        Returns a dictionary with the smart events
        """

        logger = logging.getLogger(__name__)
        logger.info("Getting NDI smart events for site group %s" % fabric_name)
        __output = {}

        # Test Prefix used to classify tests as comming from ACI vetR
        __test_prefix = "nae_"

        # Establish login session if not already logged in
        if not self.authentication_header:
            if not self.login():
                return False

        # Define start and end time for smart even query
        # start_time is 1 year prior to current time
        __start_time = "%s-%s-%s" % (datetime.now().year - 1, datetime.now().strftime('%m'), datetime.now().strftime('%d'))
        __end_time = "%s-%s-%s" % (datetime.now().year, datetime.now().strftime('%m'), datetime.now().strftime('%d'))

        # Query smart events
        __max_response_count = 100
        __success, __response = self.ndi_get_smart_events_summary_by_assurance_group_and_offset(assurance_group, __start_time, __end_time, __max_response_count, 0)
        if __success:
            if "totalResultsCount" in __response.keys():
                __total_page_count = -(-int(__response["totalResultsCount"]) // __max_response_count)
                logger.info(
                    "There are {} pages of smart events in total (zero indexed)".format(
                        __total_page_count
                    )
                )
                logger.debug("Found {} smart event entries on page 0".format(len(__response["entries"])))
            else:
                logger.debug(
                    "There are 0 smart events found (totalResultsCount key in results missing)"
                )
                return (True, __output)

            # Iterate through the smart events
            for __event in __response["entries"]:
                __event_name = __test_prefix + __event["mnemonicTitle"]

                # Build nested dictionary structure if not already in place
                if __event_name not in __output.keys():
                    __output[__event_name] = {}
                if "event_list" not in __output[__event_name].keys():
                    __output[__event_name]["event_list"] = []
                if "severity" not in __output[__event_name].keys():
                    __output[__event_name]["severity"] = ""
                if "event_list" not in __output[__event_name].keys():
                    __output[__event_name]["event_list"] = []
                if "data_source" not in __output[__event_name].keys():
                    __output[__event_name]["data_source"] = ""

                # Add smart event details to output dictionary
                __output[__event_name]["description"] = __event["anomalyStr"]
                __output[__event_name]["severity"] = __event["severity"]
                __output[__event_name]["data_source"] = "ndi"
        else:
            logger.error(
                "A failure occured while retrieving NDI smart events for assurance group '%s' (offset 0)"
            ) % assurance_group
            return (False, "")

        # Request addtional pages of smart events if they exist
        if __total_page_count > 1:
            __current_page_count = 1
            while __current_page_count < __total_page_count:
                logger.info(
                    "Retrieving page {} of smart events".format(__current_page_count)
                )
                __success, __response = self.ndi_get_smart_events_summary_by_assurance_group_and_offset(assurance_group, __start_time, __end_time, __max_response_count, __current_page_count*__max_response_count)

                if __success:
                    logger.debug("Found {} smart event entries on page {}".format(len(__response["entries"]), __current_page_count))

                    # Iterate through the smart events
                    for __event in __response["entries"]:
                        __event_name = __test_prefix + __event["mnemonicTitle"]

                        # Build nested dictionary structure if not already in place
                        if __event_name not in __output.keys():
                            __output[__event_name] = {}
                        if "event_list" not in __output[__event_name].keys():
                            __output[__event_name]["event_list"] = []
                        if "severity" not in __output[__event_name].keys():
                            __output[__event_name]["severity"] = ""

                        # Add smart event details to output dictionary
                        __output[__event_name]["description"] = __event["anomalyStr"]
                        __output[__event_name]["severity"] = __event["severity"]

                        # Increment current page count
                        __current_page_count = __current_page_count + 1
                else:
                    logger.error(
                        "A failure occured while retrieving NAE smart events for assurance group '{}' page {}".format(
                            assurance_group, __current_page_count
                        )
                    )
                    return (False, "")

        # Maintain a list of events without details
        __empty_events = []

        # Query Smart Event Details
        for __event in __output.keys():
            # Strip __test_prefix from event_name
            __event_name = __event.split(__test_prefix)[1]

            # Get Event Details
            logger.info(
                "Getting NDI smart event Details for event {}".format(__event_name)
            )

            __success, __response = self.ndi_get_smart_event_details_by_fabric_name_and_offset(assurance_group, fabric_name, __event_name, __start_time, __end_time, __max_response_count, 0)

            if __success:
                if "totalResultsCount" in __response.keys():
                    __total_page_count = -(-int(__response["totalResultsCount"]) // __max_response_count)
                    logger.info(
                        "There are {} pages of smart event details for smart event '{} in total (zero indexed)".format(
                            __total_page_count,
                            __event_name
                        )
                    )
                    logger.debug("Found {} smart event details on page 0".format(len(__response["entries"])))
                else:
                    logger.debug(
                        "There are 0 smart events details found (totalResultsCount key in results missing)"
                    )
                    logging.warning("No smart event details was found for event '%s'. Skipping this smart event" % __event)
                    __empty_events.append(__event)
                    continue


                # Append Smart Event details to output
                for __detailed_info in __response["entries"]:
                    try:
                        __output[__event]["event_list"].append(__detailed_info["entityNameList"])
                    except KeyError:
                        logger.debug("No smart event details (entityNameList) found for smart event '{}'".format(__event_name))

                # Check if detailed event entries has beeen collected.
                # If not, then add smart event to list of empty events
                if len(__output[__event]["event_list"]) == 0:
                    logging.warning("No smart event details was found for event '%s'. Skipping this smart event" % __event)
                    __empty_events.append(__event)

            else:
                logger.warning(f"A failure occured while retrieving NDI smart event details for smart event '{__event_name}'. Skipping this smart event")
                __empty_events.append(__event)
                continue

            # Request addtional pages of smart event details if they exist
            if __total_page_count > 1:
                __current_page_count = 1
                while __current_page_count < __total_page_count:
                    logger.info(
                        "Retrieving page {} of smart events".format(__current_page_count)
                    )
                    __success, __response = self.ndi_get_smart_event_details_by_fabric_name_and_offset(assurance_group, fabric_name, __event_name, __start_time, __end_time, __max_response_count, __current_page_count*__max_response_count)

                    if __success:
                        logger.debug("Found {} smart event details on page {}".format(len(__response["entries"]), __current_page_count))

                        # Append Smart Event details to output
                        for __detailed_info in __response["entries"]:
                            try:
                                __output[__event]["event_list"].append(__detailed_info["entityNameList"])
                            except KeyError:
                                logger.debug("No smart event details (entityNameList) fround for smart event '{}'".format(__event_name))


                        # Increment current page count
                        __current_page_count = __current_page_count + 1
                    else:
                        logger.error(
                            "A failure occured while retrieving NDI smart event details for assurance group '%s' and smart event '%s' (offset %s)"
                        ) % (assurance_group, __event_name, __current_page_count*__max_response_count)
                        return (False, "")

        # Remove empty NDI smart events
        if len(__empty_events) > 0:
            logger.debug(f'Removing {len(__empty_events)} empty NDI smart events')
            for __item in __empty_events:
                __output.pop(__item)

        # Return smart events
        return (True, __output, __empty_events)

def nae_retrieve_smart_events(
    hostname: str, username: str, password: str, assurance_group: str, version: str
):
    """
    "Glue" function to perform the various NAE related tasks in order to retrieve the smart
    events for the specified assurance group
    """

    logger = logging.getLogger(__name__)
    __nae = nae_session("https", hostname, username, password, version)

    # NAE operations
    if version == "nae":
        # Get NAE fabric ID
        __success, __nae_fabridId = __nae.nae_get_fabric_id_by_assurance_group(
            assurance_group
        )
        if not __success:
            logger.error(
                "Unable to to get NAE fabric id for assurance group '%s', exiting..."
                % assurance_group
            )
            exit(1)

        # Get NAE epoch ID
        __success, __nae_epochId = __nae.nae_get_epoch_id_by_fabric_id(__nae_fabridId)
        if not __success:
            logger.error(
                "Unable to to get last NAE epoch id for fabric id '%s', aborting NAE analysis"
                % __nae_fabridId
            )
            __empty_dict = dict()
            return __empty_dict

        # Get NAE smart events
        __success, __nae_findings = __nae.nae_get_smart_events_by_epoch_id(__nae_epochId)
        if not __success:
            logger.error(
                "Unable to to get NAE smart event list for epoch id '%s', exiting..."
                % __nae_epochId
            )
            exit(1)

        logger.info("Found %s NAE smart event types" % len(__nae_findings.keys()))
        return(__nae_findings, [])

    # NDI operations
    elif version == "ndi":
        # Get fabric name
        __success, __ndi_fabridName = __nae.ndi_get_fabric_name_by_assurance_group(
            assurance_group
        )
        if not __success:
            logger.error(
                "Unable to to get NDI fabric name for assurance group '%s', exiting..."
                % assurance_group
            )
            exit(1)

        # Get NDI smart events
        __success, __ndi_findings, __empty_events = __nae.ndi_get_smart_events_by_fabric_name(assurance_group, __ndi_fabridName)
        if not __success:
            logger.error(
                "Unable to to get NDI smart event list for site group '%s', exiting..."
                % assurance_group
            )
            exit(1)

        return(__ndi_findings, __empty_events)

def nae_render_smart_events(
    template_path: str, nae_smart_events: dict, ignore_list: dict, nae_version: str
):
    """
    Renders document templates for the NAE smart events

    Input:
        template path - Path to the template folder
        nae_smart_events - Dictionary containing the NAE smart events (output of the nae_retrieve_smart_events function)
        ignore_list - Dictionary containing the list of findings to be ignored
        nae_version - String indicating if NAE or NDI smart events are to be rendered

    Output:
        __rendered_output - Dictionary with the document sniplets for each NAE smart events
    """

    logger = logging.getLogger(__name__)
    if nae_version == "ndi":
        logger.info("Rendering NDI smart events")
    else:
        logger.info("Rendering NAE smart events")
    __rendered_output = {}
    __audit_template = TemplateRender(template_path)
    for __event in nae_smart_events:
        # Massage event name to separate tool name from event name
        __event_components = __event.split("_")
        __event_name = "_".join(__event_components[1:])

        # Check if event should be ignored
        if __event_name in ignore_list["nae"]:
            if nae_version == "ndi":
                logger.debug(
                    "SKIPPING Rendering of NDI event '%s' as per the ignore list"
                    % __event_name
                )
            else:
                logger.debug(
                    "SKIPPING Rendering of NAE event '%s' as per the ignore list"
                    % __event_name
                )
            continue

        # define template filename and prepare data structure for rendered event
        __template_file = __event + ".md"
        __rendered_output[__event] = dict()

        # Render template
        (
            __success,
            __rendered_template_output,
        ) = __audit_template.render_template(__template_file, nae_smart_events[__event])

        if __success:
            __rendered_output[__event]["content"] = __rendered_template_output
            # Extract event metadata from successfully rendered templates
            if __rendered_output[__event]["content"] is not None:
                __success, __metadata = get_template_metadata(
                    __rendered_output[__event]["content"], __template_file
                )
                if __success:
                    # In case of NDI execution, check if template supports NDI
                    if nae_version == "ndi":
                        try:
                            if __metadata["ndi_support"]:
                                __rendered_output[__event]["metadata"] = __metadata
                            else:
                                # Template does not support NDI, reset content and generate error flag
                                __rendered_output[__event]["content"] = ""
                                __rendered_output[__event]["metadata"] = None
                                __rendered_output[__event]["error"] = "NDI support missing in template '%s'" % __template_file
                                logger.error(
                                    "NDI support missing in template '%s'" % __template_file
                                )
                                # Send telemetry inforamtion about missing NDI support in template
                                telemetry_message = {
                                    "timestamp": str(datetime.now()),
                                    "toolName": "aci_proactive_audit",
                                    "exception": "TemplateNDISupportMissing",
                                    "template": __template_file,
                                    "data": nae_smart_events[__event],
                                }
                                submit_telemetry(telemetry_message)
                        except KeyError:
                            # Template does not support NDI, reset content and generate error flag
                            __rendered_output[__event]["content"] = ""
                            __rendered_output[__event]["metadata"] = None
                            __rendered_output[__event]["error"] = "NDI support missing in template '%s'" % __template_file
                            logger.error(
                                "NDI support missing in template '%s'" % __template_file
                            )
                            # Send telemetry inforamtion about missing NDI support in template
                            telemetry_message = {
                                "timestamp": str(datetime.now()),
                                "toolName": "aci_proactive_audit",
                                "exception": "TemplateNDISupportMissing",
                                "template": __template_file,
                                "data": nae_smart_events[__event],
                            }
                            submit_telemetry(telemetry_message)
                    else:
                        __rendered_output[__event]["metadata"] = __metadata
                else:
                    __rendered_output[__event]["metadata"] = None
                    __rendered_output[__event][
                        "error"
                    ] = "Template metadata extraction failed"
        else:
            # Template rendering failed
            # Add error message to internal data structure
            __rendered_output[__event]["content"] = None
            __rendered_output[__event]["metadata"] = None
            __rendered_output[__event]["error"] = __rendered_template_output

    return __rendered_output


def ssd_analyze_output(ssd_data: str):
    """
    Analyses the output of ACI SSD Script and extracts the recommended actions

    Input:
        ssd_data - string containing SSD report output

    Output:
        __output - Dictionary with the recommended actions, key is the test type and value is the result from ACI SSD
    """
    logger = logging.getLogger(__name__)
    logger.info("Analysing SSD input")

    # SSD Thresholds
    __ssd_thresholds_major = 80.0
    __ssd_thresholds_critical = 90.0

    # Test Prefix and Name used to classify tests as comming from ACI SSD Script
    __test_name = "ssd_faults"

    # Analysis output and default to action recommended being false
    __ssd_action = dict()
    __ssd_action["actionRecommended"] = False
    __ssd_action["affected_nodes"] = dict()
    __ssd_action["affected_nodes"]["critical"] = list()
    __ssd_action["affected_nodes"]["major"] = list()

    # Extract node info from ssd output
    __ssd_usage = None
    logger.debug("Analysing SSD input")
    for __line in ssd_data:
        # Strip line
        __line = __line.strip()

        # Analyse only relevant lines
        if __line.startswith("Node:"):
            # End of previous node entry, process findings (if any)
            if __ssd_usage is not None:
                for __entry in __ssd_usage.keys():
                    # Skip 'node' and 'model' entries, which are used for node-id
                    if __entry == "node":
                        logger.debug("Found {}".format(__ssd_usage[__entry]))
                        continue
                    if __entry == "model":
                        logger.debug("Model: {}".format(__ssd_usage[__entry]))
                        continue

                    logger.debug(
                        "{} ({}): {} %".format(
                            __ssd_usage[__entry]["description"],
                            __ssd_usage[__entry]["id"],
                            __ssd_usage[__entry]["usage"],
                        )
                    )

                    # Check critical threshold
                    if __ssd_usage[__entry]["usage"] >= __ssd_thresholds_critical:
                        __ssd_action["actionRecommended"] = True
                        if (
                            __ssd_usage["node"]
                            not in __ssd_action["affected_nodes"]["critical"]
                        ):
                            logger.debug(
                                "Usage type {} exceeds critical threshold ({}% >= {}%)".format(
                                    __ssd_usage[__entry]["id"],
                                    __ssd_usage[__entry]["usage"],
                                    __ssd_thresholds_critical,
                                )
                            )
                            __ssd_action["affected_nodes"]["critical"].append(
                                __ssd_usage["node"]
                            )

                    # Check major threshold
                    if __ssd_usage[__entry]["usage"] >= __ssd_thresholds_major:
                        __ssd_action["actionRecommended"] = True
                        # Avoid adding entries to major, if already present in critical
                        if (
                            __ssd_usage["node"]
                            not in __ssd_action["affected_nodes"]["major"]
                            and __ssd_usage["node"]
                            not in __ssd_action["affected_nodes"]["critical"]
                        ):
                            logger.debug(
                                "Usage type {} exceeds major threshold ({}% >= {}%)".format(
                                    __ssd_usage[__entry]["id"],
                                    __ssd_usage[__entry]["usage"],
                                    __ssd_thresholds_major,
                                )
                            )
                            __ssd_action["affected_nodes"]["major"].append(
                                __ssd_usage["node"]
                            )

                # Reset variable
                __ssd_usage = None

            # Capture Node ID
            __line_match = re.search("^Node: (\d+)$", __line)
            if __line_match:
                __node_id = __line_match.group(1)
                __ssd_usage = dict()
                __ssd_usage["node"] = "node-" + __node_id
        # Capture SSD Model
        elif __line.startswith("Model:"):
            __line_match = re.search("^Model: (.+)$", __line)
            if __line_match:
                if type(__ssd_usage) == dict:
                    __ssd_model = __line_match.group(1)
                    __ssd_usage["model"] = __ssd_model
                else:
                    logger.error(
                        "Something went wrong when parsing 'model' in the SSD input"
                    )
        # Skip empty lines
        elif __line == "":
            continue
        # Match SSD usage lines and provide list with Type_description, Type_id, usage (in percent)
        else:
            __line_match = re.search("^(.+)\s+\((\d+)\):.+\((.+)%\)$", __line)
            if __line_match:
                if type(__ssd_usage) == dict:
                    __type_description = __line_match.group(1)
                    __type_id = __line_match.group(2)
                    __type_usage = float(__line_match.group(3))
                    __ssd_usage["type_" + __type_id] = {
                        "description": __type_description,
                        "id": __type_id,
                        "usage": __type_usage,
                    }
                else:
                    logger.error(
                        "Something went wrong when parsing usage entries in the SSD input"
                    )

    # Check threshold for last node entry in input
    if __ssd_usage is not None:
        for __entry in __ssd_usage.keys():
            # Skip 'node' and 'model' entries, which are used for node-id
            if __entry == "node":
                logger.debug("Found {}".format(__ssd_usage[__entry]))
                continue
            if __entry == "model":
                logger.debug("Model: {}".format(__ssd_usage[__entry]))
                continue

            logger.debug(
                "{} ({}): {} %".format(
                    __ssd_usage[__entry]["description"],
                    __ssd_usage[__entry]["id"],
                    __ssd_usage[__entry]["usage"],
                )
            )

            # Check critical threshold
            if __ssd_usage[__entry]["usage"] >= __ssd_thresholds_critical:
                __ssd_action["actionRecommended"] = True
                if (
                    __ssd_usage["node"]
                    not in __ssd_action["affected_nodes"]["critical"]
                ):
                    logger.debug(
                        "Usage type {} exceeds critical threshold ({}% >= {}%)".format(
                            __ssd_usage[__entry]["id"],
                            __ssd_usage[__entry]["usage"],
                            __ssd_thresholds_critical,
                        )
                    )
                    __ssd_action["affected_nodes"]["critical"].append(
                        __ssd_usage["node"]
                    )

            # Check major threshold
            if __ssd_usage[__entry]["usage"] >= __ssd_thresholds_major:
                __ssd_action["actionRecommended"] = True
                # Avoid adding entries to major, if already present in critical
                if (
                    __ssd_usage["node"] not in __ssd_action["affected_nodes"]["major"]
                    and __ssd_usage["node"]
                    not in __ssd_action["affected_nodes"]["critical"]
                ):
                    logger.debug(
                        "Usage type {} exceeds major threshold ({}% >= {}%)".format(
                            __ssd_usage[__entry]["id"],
                            __ssd_usage[__entry]["usage"],
                            __ssd_thresholds_major,
                        )
                    )
                    __ssd_action["affected_nodes"]["major"].append(__ssd_usage["node"])

    # Add recommended action to output if present
    __output = dict()
    if __ssd_action["actionRecommended"]:
        __output[__test_name] = __ssd_action

    logger.info("Found %s ACI SSD recommended actions" % len(__output))
    return __output


def check_audit_warnings(events: dict, warning_list: dict):
    logger = logging.getLogger(__name__)
    logger.info("Checking for known issues while running the collector tool")
    for __event in events:
        # Massage event name to separate tool name from event name
        __event_components = __event.split("_")
        __tool = __event_components[0]
        __event_name = "_".join(__event_components[1:])
        if __event_name in warning_list[__tool]:
            if __tool.lower() == "vetr":
                logger.warning(
                    "Found vetR action '{}' in the analys. This may indicate errors during execution of vetR collector".format(
                        __event_name
                    )
                )
            elif __tool.lower() == "nae":
                logger.warning(
                    "Found NAE smart event '{}' in the analys. This may indicate errors during collection of NAE offline bundle".format(
                        __event_name
                    )
                )
            else:
                logger.warning(
                    "Found event '{}' in the analys. This may indicate errors during data collection".format(
                        __event_name
                    )
                )


def create_findings_summary_table(findings: dict):
    """
    Creates sorted lists of findings based on the severity metadata of each finding
    """
    logger = logging.getLogger(__name__)

    # List of findingentries that should not be included in priority table as they are not actual findings
    __ignore_findings = [
        "vetR_analysis_enabled",
        "nae_analysis_enabled",
        "ssd_analysis_enabled",
        "main_document",
        "hw_inventory",
    ]

    # Define severity mapping schema
    __priority_mapping_schema = {
        "emergency": "1 - Critical",
        "alert": "1 - Critical",
        "critical": "1 - Critical",
        "error": "2 - Warning",
        "warning": "2 - Warning",
        "notice": "3 - Informational",
        "info": "3 - Informational",
        "debug": "99 - Debug",
        "ok": "0 - Health",
        "invisible": "100 - Invisible",
    }

    # Iterate through the findings
    __summary_table = list()
    for __item in findings:
        # Skip non-finding entries
        if __item in __ignore_findings:
            logger.debug(
                "Skipping entry '{}' as per findings ignore list".format(__item)
            )
            continue
        # Errors occured during template rendering and/or metadata extraction
        elif "error" in findings[__item]:
            # Template missing
            if findings[__item]["error"].startswith("Template missing"):
                if "missing_templates" not in findings["main_document"]:
                    findings["main_document"]["missing_templates"] = list()
                findings["main_document"]["missing_templates"].append(__item)
            # Template missing NDI support
            if findings[__item]["error"].startswith("NDI support missing in template"):
                if "templates_missing_ndi_support" not in findings["main_document"]:
                    findings["main_document"]["templates_missing_ndi_support"] = list()
                findings["main_document"]["templates_missing_ndi_support"].append(__item)
            # Template syntax error
            elif findings[__item]["error"].startswith("Syntax error in Template"):
                if "syntax_error_templates" not in findings["main_document"]:
                    findings["main_document"]["syntax_error_templates"] = list()
                findings["main_document"]["syntax_error_templates"].append(__item)
            # Template undefined error
            elif findings[__item]["error"].startswith(
                "Undefined error while rendering template"
            ):
                if "undefined_error_templates" not in findings["main_document"]:
                    findings["main_document"]["undefined_error_templates"] = list()
                findings["main_document"]["undefined_error_templates"].append(__item)
        # Process Metadata to create summary table
        else:
            try:
                if findings[__item]["metadata"] is not None:
                    # Find tool source (number are used to fix sort in report)
                    __item_source_components = __item.split("_")
                    if __item_source_components[0] == "ssd":
                        __item_source = "1 - ssd"
                    elif __item_source_components[0] == "vetR":
                        __item_source = "2 - vetR"
                    elif __item_source_components[0] == "nae":
                        __item_source = "3 - nae"
                    else:
                        __item_source = "99 - " + __item_source_components[0]

                    # Find priority
                    try:
                        __item_severity = findings[__item]["metadata"]["severity"]
                        __item_priority = __priority_mapping_schema[
                            __item_severity.lower()
                        ]
                    except KeyError:
                        logger.error(
                            "An Error while looking up looking up severity metadata for finding `{}`".format(
                                __item
                            )
                        )
                        __item_priority = "-"

                    # Find affected count
                    try:
                        __item_affected_count = findings[__item]["metadata"][
                            "affected_count"
                        ]
                    except KeyError:
                        # Provide a default value in order to render summary table correct
                        __item_affected_count = "-"

                    # Find Finding headline
                    try:
                        __item_headline_entries = re.findall(
                            "#+\s(.+)\n", findings[__item]["content"]
                        )
                        __item_headline = __item_headline_entries[0]
                    except KeyError:
                        logger.error(
                            "An Error while looking up looking up content for finding `{}`".format(
                                __item
                            )
                        )
                        __item_headline = "-"

                    # Defining findings details
                    __finding_details = {
                        "name": __item,
                        "headline": __item_headline,
                        "tool_source": __item_source,
                        "priority": __item_priority,
                        "affected_count": __item_affected_count,
                    }
                    __summary_table.append(__finding_details)
                else:
                    logger.debug(
                        "Unable to read metadata for finding `{}`".format(__item)
                    )
            except KeyError:
                logger.debug(
                    "Metadata not defined for fiding '{}'".format(findings[__item])
                )

    # Add priority table to main_document key in findings
    findings["main_document"]["summary_table"] = __summary_table
    return findings


def generate_audit_report(cmd_parameters: dict):
    """
    Generates the audit report based on the findings from ACI vetR and NAE smart events
    """

    # Verify command parameters
    cmd_parameters = verify_input_parameters(cmd_parameters)

    # Logging config
    if cmd_parameters["debug"]:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        level=log_level,
        handlers=[
            logging.FileHandler(
                os.path.join(os.path.dirname(__file__), "execution_log.txt"), mode="w"
            ),
            logging.StreamHandler(),
        ],
    )
    logger = logging.getLogger(__name__)

    logger.info("Starting ACI Proactive Audit script")
    logger.info("Tasks to execute: {}".format(cmd_parameters["tasks"]))

    # Set global variable to reflect incognito mode (used for submission of stats and telemetry)
    global INCOGNITO_EXEC_MODE
    if cmd_parameters["incognito"]:
        INCOGNITO_EXEC_MODE = True
    else:
        INCOGNITO_EXEC_MODE = False

    # Default file locations
    template_path = os.path.join(os.path.dirname(__file__), "templates/")
    docx_formatting_path = os.path.join(os.path.dirname(__file__), "docx_formatting/")
    if (
        "/" in cmd_parameters["audit_output"]
    ):  # Check if defined output file has is a full "path" or not
        output_path = ""
    else:
        output_path = os.path.dirname(__file__)
    output_file = cmd_parameters["audit_output"].split(
        "."
    )  # split filename into list based on each . in the file name
    output_file_base = ".".join(
        output_file[:-1]
    )  # re-assemble filename except for the last extention
    filename_md = os.path.join(output_path, output_file_base + ".md")
    filename_docx = os.path.join(output_path, output_file_base + ".docx")
    filename_json = os.path.join(output_path, output_file_base + ".json")
    filename_finding_json = cmd_parameters["findings_input"]
    audit_ignore_list = os.path.join(
        os.path.dirname(__file__), cmd_parameters["audit_ignore_list"]
    )
    audit_warning_list = os.path.join(
        os.path.dirname(__file__), cmd_parameters["audit_warning_list"]
    )

    # Check is specified language is supported and update template_path accordingly
    supported_languages = get_subdir(template_path)
    if cmd_parameters["language"] in supported_languages:
        logger.info("Specificed language is '{}'".format(cmd_parameters["language"]))
        template_path = os.path.join(template_path, cmd_parameters["language"] + "/")
    else:
        logger.error(
            "Specified language '{}' is NOT supported by the too.".format(
                cmd_parameters["language"]
            )
        )
        logger.error("Supported languages are: {}".format(supported_languages))
        exit(1)

    # Import list of tests/findings to warn about or skipped (if any)
    audit_ignore_list = read_yaml(cmd_parameters["audit_ignore_list"])
    audit_waring_list = read_yaml(audit_warning_list)

    # Get ACI vetR and NAE findings
    if "get_findings" in cmd_parameters["tasks"]:
        # Analyse ACI vetR output and render document templates for recommended actions
        if cmd_parameters["enable_vetr"]:
            logger.info("Starting ACI vetR tasks")
            logger.info("Reading ACI vetR output ('%s')" % cmd_parameters["vetR_input"])
            vetR_data = read_json(cmd_parameters["vetR_input"])
            vetR_version = vetr_check_dataformat(vetR_data)
            # Convert dataformat if needed
            if vetR_version == "dataformat_2_0_0":
                logger.warning(
                    "Older version of ACI vetR was used, this means that not all checks may have been performed !"
                )
                vetR_data = vetr_convert_dataformat(vetR_data)
            vetR_findings = vetr_analyse_output(vetR_data)
            check_audit_warnings(vetR_findings, audit_waring_list)
            vetR_audit_output = vetr_render_actions(
                template_path, vetR_findings, audit_ignore_list
            )

        # Analyse NAE output
        if cmd_parameters["enable_nae"]:
            if cmd_parameters["nae_version"] == "ndi":
                logger.info("Starting NDI tasks")
            else:
                logger.info("Starting NAE tasks")

            (nae_findings, nae_empty_events) = nae_retrieve_smart_events(
                cmd_parameters["nae_hostname"],
                cmd_parameters["nae_username"],
                cmd_parameters["nae_password"],
                cmd_parameters["nae_assurance_group"],
                cmd_parameters["nae_version"]
            )
            # Skip rendering of NAE templates if no findings was found
            if len(nae_findings) == 0:
                if cmd_parameters["nae_version"] == "ndi":
                    logging.info(
                        "Found 0 NDI smart events containing detailed information. Skipping rendering of NAE templates"
                    )
                    logging.info(f"Found {len(nae_empty_events)} NDI smart events without details")
                else:
                    logging.info(
                        "Found 0 NAE smart events. Skipping rendering of NAE templates"
                    )
                    logging.info(f"Found {len(nae_empty_events)} NAE smart events without details")
                nae_audit_output = dict()
            else:
                if cmd_parameters["nae_version"] == "ndi":
                    logging.info(f"Found {len(nae_findings)} NDI smart events.")
                    logging.info(f"Found {len(nae_empty_events)} NDI smart events without details")
                else:
                    logging.info(f"Found {len(nae_findings)} NAE smart events.")
                    logging.info(f"Found {len(nae_empty_events)} NAE smart events without details")
                check_audit_warnings(nae_findings, audit_waring_list)
                nae_audit_output = nae_render_smart_events(
                    template_path, nae_findings, audit_ignore_list, cmd_parameters["nae_version"]
                )

        # Analyze SSD output
        if cmd_parameters["enable_ssd"]:
            logger.info("Starting SSD tasks")
            ssd_data = read_txt(cmd_parameters["ssd_input"])
            ssd_findings = ssd_analyze_output(ssd_data)
            # Skip rendering of SSD templates if no findings was found
            if len(ssd_findings) == 0:
                logging.info(
                    "Found 0 SSD recommended actions. Skipping rendering of SSD templates"
                )
                ssd_audit_output = dict()
            else:
                check_audit_warnings(ssd_findings, audit_waring_list)
                ssd_audit_output = vetr_render_actions(
                    template_path, ssd_findings, audit_ignore_list
                )

        # Combining findings into a single dictionary
        logger.info("Combining findings from the different inputs vetR, NAE/NDI, SSD, etc.")
        if (
            cmd_parameters["enable_vetr"]
            and cmd_parameters["enable_nae"]
            and cmd_parameters["enable_ssd"]
        ):
            combined_findings = vetR_audit_output.copy()
            combined_findings.update(nae_audit_output)
            combined_findings.update(ssd_audit_output)
            combined_findings["vetR_analysis_enabled"] = True
            combined_findings["nae_analysis_enabled"] = True
            combined_findings["ssd_analysis_enabled"] = True
        elif cmd_parameters["enable_vetr"] and cmd_parameters["enable_nae"]:
            combined_findings = vetR_audit_output.copy()
            combined_findings.update(nae_audit_output)
            combined_findings["vetR_analysis_enabled"] = True
            combined_findings["nae_analysis_enabled"] = True
            combined_findings["ssd_analysis_enabled"] = False
        elif cmd_parameters["enable_vetr"] and cmd_parameters["enable_ssd"]:
            combined_findings = vetR_audit_output.copy()
            combined_findings.update(ssd_audit_output)
            combined_findings["vetR_analysis_enabled"] = True
            combined_findings["nae_analysis_enabled"] = False
            combined_findings["ssd_analysis_enabled"] = True
        elif cmd_parameters["enable_nae"] and cmd_parameters["enable_ssd"]:
            combined_findings = nae_audit_output.copy()
            combined_findings.update(ssd_audit_output)
            combined_findings["vetR_analysis_enabled"] = False
            combined_findings["nae_analysis_enabled"] = True
            combined_findings["ssd_analysis_enabled"] = True
        elif cmd_parameters["enable_vetr"]:
            combined_findings = vetR_audit_output.copy()
            combined_findings["vetR_analysis_enabled"] = True
            combined_findings["nae_analysis_enabled"] = False
            combined_findings["ssd_analysis_enabled"] = False
        elif cmd_parameters["enable_nae"]:
            combined_findings = nae_audit_output.copy()
            combined_findings["vetR_analysis_enabled"] = False
            combined_findings["nae_analysis_enabled"] = True
            combined_findings["ssd_analysis_enabled"] = False
        elif cmd_parameters["enable_ssd"]:
            combined_findings = ssd_audit_output.copy()
            combined_findings["vetR_analysis_enabled"] = False
            combined_findings["nae_analysis_enabled"] = False
            combined_findings["ssd_analysis_enabled"] = True
        else:
            logger.error(
                "Processing of both ACI vetR, NAE, and SSD disabled, exiting....."
            )
            exit(1)

        # Add Customer and Engineer name
        combined_findings["main_document"] = {}
        combined_findings["main_document"]["customer_name"] = cmd_parameters[
            "customer_name"
        ]
        combined_findings["main_document"]["engineer_name"] = cmd_parameters[
            "engineer_name"
        ]

        # Add list of empty NAE events to main_document so that warning can be presented to end-user
        if cmd_parameters["enable_nae"] and len(nae_empty_events) > 0:
            combined_findings["main_document"]["nae_empty_events"] = nae_empty_events

        # Add Inventory and SW information
        if cmd_parameters["enable_vetr"]:
            try:
                if "fabricStats" in vetR_data["stats"]:
                    combined_findings["main_document"]["fabricStats"] = dict()
                    combined_findings["main_document"]["fabricStats"][
                        "controllers"
                    ] = vetR_data["stats"]["fabricStats"]["controllers"]
                    combined_findings["main_document"]["fabricStats"][
                        "leaves"
                    ] = vetR_data["stats"]["fabricStats"]["leaves"]
                    combined_findings["main_document"]["fabricStats"][
                        "spines"
                    ] = vetR_data["stats"]["fabricStats"]["spines"]
                if "stats" in vetR_data["tenant"]:
                    combined_findings["main_document"]["tenantStats"] = vetR_data[
                        "tenant"
                    ]["stats"]["statsByTenant"]
                if "firmwareVersion" in vetR_data["admin"]:
                    combined_findings["main_document"]["fabricVersion"] = dict()
                    combined_findings["main_document"]["fabricVersion"][
                        "apicVersion"
                    ] = vetR_data["admin"]["firmwareVersion"]["apicVersion"]
                    combined_findings["main_document"]["fabricVersion"][
                        "switchVersion"
                    ] = vetR_data["admin"]["firmwareVersion"]["switchVersion"]
                    combined_findings["main_document"]["fabricVersion"][
                        "multipleVersions"
                    ] = vetR_data["admin"]["firmwareVersion"]["state"][
                        "hasMultipleVersions"
                    ]
            except KeyError:
                combined_findings["main_document"]["fabricStats"] = None
                combined_findings["main_document"]["tenantStats"] = None
                combined_findings["main_document"]["fabricVersion"] = {}
                combined_findings["main_document"]["fabricVersion"]["apicVersion"] = "N/A"
                combined_findings["main_document"]["fabricVersion"]["switchVersion"] = "N/A"
                combined_findings["main_document"]["fabricVersion"]["multipleVersions"] = False
        else:
            # Extracting HW Inventory from NAE not implemented yet
            combined_findings["main_document"]["fabricStats"] = None
            combined_findings["main_document"]["tenantStats"] = None
            combined_findings["main_document"]["fabricVersion"] = {}
            combined_findings["main_document"]["fabricVersion"]["apicVersion"] = "N/A"
            combined_findings["main_document"]["fabricVersion"]["switchVersion"] = "N/A"
            combined_findings["main_document"]["fabricVersion"]["multipleVersions"] = False

        # Extract HW Inventory information used for BlowTorch Integration
        if cmd_parameters["enable_vetr"]:
            try:
                if "devices" in vetR_data["stats"]["inventory"]:
                    combined_findings["hw_inventory"] = vetR_data["stats"]["inventory"][
                        "devices"
                    ]
            except KeyError:
                combined_findings["hw_inventory"] = None
        else:
            # Extracting HW Inventory from NAE not implemented yet
            combined_findings["hw_inventory"] = None

    # Import findings from previous generated JSON
    if "import_findings" in cmd_parameters["tasks"]:
        logger.info("Starting to import findings from JSON")
        combined_findings = read_json(filename_finding_json)

        # Count number of imported findings
        tool_stats = dict()
        tool_stats["vetr_count"] = 0
        tool_stats["nae_count"] = 0
        tool_stats["ssd_count"] = 0
        for key in combined_findings:
            if key.startswith("vetR_") and key != "vetR_analysis_enabled":
                tool_stats["vetr_count"] = tool_stats["vetr_count"] + 1
            elif key.startswith("nae_") and key != "nae_analysis_enabled":
                tool_stats["nae_count"] = tool_stats["nae_count"] + 1
            elif key.startswith("ssd_") and key != "ssd_analysis_enabled":
                tool_stats["ssd_count"] = tool_stats["ssd_count"] + 1

        logger.info(
            "Imported %s ACI vetR recommended actions" % tool_stats["vetr_count"]
        )
        logger.info("Imported %s NAE smart event findings" % tool_stats["nae_count"])
        logger.info("Imported %s SSD recommended actions" % tool_stats["ssd_count"])

    # Export combined findings in json format
    if "export_findings" in cmd_parameters["tasks"]:
        try:
            with open(filename_json, "w", encoding="utf-8") as f:
                json.dump(combined_findings, f)
                logger.info(
                    "Writing audit report in json format to disk (%s)" % filename_json
                )
        except Exception:
            logger.error("An error occured while writing audit report to disk")
            exit(1)

    # Render final report and convert to docx format
    if "render_report" in cmd_parameters["tasks"]:
        logger.info("Starting creation of audit report")
        audit_template = TemplateRender(template_path)

        # Add current date to findings
        today = date.today()
        combined_findings["main_document"]["date"] = today.strftime("%B %d, %Y")

        # Check if Customer and Engineer name
        try:
            if "customer_name" not in combined_findings["main_document"]:
                if cmd_parameters["customer_name"] != "":
                    combined_findings["main_document"][
                        "customer_name"
                    ] = cmd_parameters["customer_name"]
                else:
                    logger.warning(
                        "Customer Name not provided, this may impact report rendering"
                    )
            if "engineer_name" not in combined_findings["main_document"]:
                if cmd_parameters["engineer_name"] != "":
                    combined_findings["main_document"] = cmd_parameters["engineer_name"]
                else:
                    logger.warning(
                        "Engineer Name not provided, this may impact report rendering"
                    )
        except KeyError:
            logger.warning(
                "An error occured while validating customer and/or engineer name. This may impact report rendering"
            )

        # Create findings priority table
        logger.info("Creating summary table of findings")
        combined_findings = create_findings_summary_table(combined_findings)

        # Render report in markdown format
        logger.info("Rendering audit report")
        __success, rendered_main_document = audit_template.render_template(
            "main_document.md", combined_findings
        )

        if not __success:
            # Rndering of main document failed, create a document with the error message
            rendered_main_document = (
                "# Rendering of document failed\nError message: %s\n\nPlease contact escallation team/tool owner"
                % rendered_main_document
            )

        # Write markdown audit report to disk
        try:
            with open(filename_md, "w", encoding="utf-8") as f:
                f.write(rendered_main_document)
                logger.info(
                    "Writing audit report in markdown format to disk (%s)" % filename_md
                )
        except Exception:
            logger.error("An error occured while writing audit report to disk")
            exit(1)

        # Convert document to disk using Pandoc
        logger.info("Starting conversion of audit report to docx format using Pandoc")

        # Check if Pandoc is in $PATH
        if shutil.which("pandoc") is None:
            logger.critical(
                "Pandoc not found in $PATH, attempting to pandoc in working directory"
            )
            pandoc = "./pandoc"
        else:
            logger.info("Pandoc found in $PATH")
            pandoc = "pandoc"

        # Converting document
        logger.info("Converting audit report from markdown to docx format")
        docx_reference = docx_formatting_path + "ref.docx"
        # Disable filter option if we revert to local pandoc in order to fail execution in BDB
        if pandoc == "./pandoc":
            args = [
                pandoc,
                "-f",
                "markdown+hard_line_breaks",
                "-t",
                "docx",
                "--reference-doc=" + docx_reference,
                "-s",
                filename_md,
                "-o",
                filename_docx,
            ]
        else:
            args = [
                pandoc,
                "-f",
                "markdown+hard_line_breaks",
                "-t",
                "docx",
                "--reference-doc=" + docx_reference,
                "-s",
                filename_md,
                "-o",
                filename_docx,
            ]
        logger.debug("Executing command: %s" % " ".join(args))
        try:
            res = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            stdout, stderr = res.communicate()
            logger.error("An error occured when executing Pandoc command, exiting....")
            logger.info(f"stdout: {stdout}")
            logger.info(f"stderr: {stderr}")
            exit(1)
        #  Wait for process to finish
        res.wait()

        # Check if an error occured while executing Pandoc
        if res.returncode != 0:
            stdout, stderr = res.communicate()
            logger.error("An error occured while converting audit report, exiting....")
            logger.info(f"stdout: {stdout}")
            logger.info(f"stderr: {stderr}")
            exit(1)

        # Convertion successful, remove temporary markdown file
        logger.info("Audit report successfully converted to docx")

        logger.debug("Removing temporary markdown file (%s)" % filename_md)
        try:
            os.remove(filename_md)
        except Exception:
            logger.error(
                "An error occured while removing temporary markddown file (%s), exiting...."
                % filename_md
            )
            exit(1)

        logger.info(
            "Please open the final report (%s) and do any final edits that may be required !"
            % filename_docx
        )


def get_args() -> argparse.Namespace:
    """Grab command arguments"""
    parser = argparse.ArgumentParser(
        description="This script generates an ACI Proactive Audit Report based on input from ACI vetR and Network Assurance Engine (NAE)"
    )
    parser.add_argument(
        "-e",
        "--engineer_name",
        dest="engineer_name",
        default=None,
        help="Name of engineer using the tool",
    )
    parser.add_argument(
        "-c",
        "--customer_name",
        dest="customer_name",
        default=None,
        help="Name of the customer for which the report is generated",
    )
    parser.add_argument(
        "-p",
        "--pid",
        dest="pid",
        help="CX Project ID",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="vetR_input",
        default="out.json",
        help="ACI vetR output file in JSON format (default: out.json)",
    )
    parser.add_argument(
        "-ssd",
        "--ssd_input",
        dest="ssd_input",
        default=None,
        help="ACI SSD script report file in TXT format ('report-xxxxx.txt')",
    )
    parser.add_argument(
        "-host",
        "--hostname",
        dest="nae_hostname",
        default=None,
        help="NAE Hostname",
    )
    parser.add_argument(
        "-user",
        "--username",
        dest="nae_username",
        default=None,
        help="NAE Username",
    )
    parser.add_argument(
        "-pass",
        "--password",
        dest="nae_password",
        default=None,
        help="NAE Password",
    )
    parser.add_argument(
        "-a",
        "--assurance-group",
        default=None,
        dest="nae_assurance_group",
        help="NAE Assurance Group",
    )
    parser.add_argument(
        "--nae_version",
        default="nae",
        dest="nae_version",
        help="NAE version (nae or ndi) with 'nae' being default",
    )
    parser.add_argument(
        "--ignore-list",
        dest="audit_ignore_list",
        default="ignore_findings.yaml",
        help="Audit Finding Ignore List (default: ignore_findings.yaml)",
    )
    parser.add_argument(
        "--warning-list",
        dest="audit_warning_list",
        default="warning_findings.yaml",
        help="Audit Finding Warning List (default: warning_findings.yaml)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="audit_output",
        default="aci_audit_report.docx",
        help="Output File Name (default: aci_audit_output.docx)",
    )
    parser.add_argument(
        "--findings_input",
        dest="findings_input",
        default="aci_audit_report.json",
        help="Input File Name for findings JSON file (default: aci_audit_output.json",
    )
    parser.add_argument(
        "--enable_vetr_analysis",
        dest="enable_vetr",
        default=True,
        help="Enable Analysis of ACI vetR Output (default: True)",
    )
    parser.add_argument(
        "--enable_nae_analysis",
        dest="enable_nae",
        default=True,
        help="Enable Analysis of NAE Smart Events (default: True)",
    )
    parser.add_argument(
        "--enable_ssd_analysis",
        dest="enable_ssd",
        default=True,
        help="Enable Analysis of NAE Smart Events (default: True)",
    )
    parser.add_argument(
        "--language",
        dest="language",
        default="en",
        help="Specify the language the generated report should use (default: en)",
    )
    parser.add_argument(
        "--incognito",
        action="store_const",
        const=True,
        default=False,
        help="Disables submission of tool usage information (NOT RECOMMENDED",
    )
    parser.add_argument(
        "--enable_debug",
        dest="debug",
        default=False,
        help="Enable debug logging",
    )
    parser.add_argument(
        "--tasks",
        dest="tasks",
        default=["get_findings", "render_report"],
        help="Controls the tasks executed by the script. Supported options are 'get_findings', 'import_findings' 'export_findings' and 'render_report' (default: ['get_findings', 'export_findings'])",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    cmd_parameters = vars(args)
    generate_audit_report(cmd_parameters)
