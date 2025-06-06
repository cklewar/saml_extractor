import argparse
import base64
import configparser
import os
import os.path
import xml.etree.ElementTree as ET
from collections import namedtuple

import boto3
import botocore
import botocore.config
import botocore.errorfactory
import gitlab

START_LEAF = "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
SECOND_LEAF = "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
SESSION_ROLE = "Session Role"
AWS_DEFAULT_CONFIG_PATH = "~/.aws/config"
AWS_DEFAULT_CREDENTIALS_PATH = "~/.aws/credentials"
SAML_DEFAULT_SESSION_DURATION = 43200
AWS_CREDENTIAL_VARS = ["aws_access_key_id", "aws_session_token", "aws_secret_access_key"]
Data = namedtuple("Data", "role_arn idp_arn")
Saml = namedtuple("Saml", "aws_access_key_id aws_session_token aws_secret_access_key")


def run(profile=None, region: str = None, idp_arn: str = None, role_arn: str = None, saml: str = None, write_to_file: bool = False, export_to_env: bool = False, print_to_stdout: bool = False) -> Saml:
    profile_name = profile or os.environ.get("AWS_PROFILE", "default")
    region_name = region or os.environ.get("AWS_DEFAULT_REGION", None)
    section_name = (profile_name if profile_name == "default" else f"profile {profile_name}")
    config_path = os.environ.get("AWS_CONFIG_FILE") or os.path.expanduser(AWS_DEFAULT_CONFIG_PATH)
    cred_path = os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or os.path.expanduser(AWS_DEFAULT_CREDENTIALS_PATH)
    config = configparser.RawConfigParser()
    config.read(config_path)
    session_duration = config.getint(section_name, "saml.session_duration") if config.has_option(section_name, "saml.session_duration") else SAML_DEFAULT_SESSION_DURATION
    principal_arn = idp_arn or config.get(section_name, "saml.idp_arn")
    role_arn = role_arn or config.get(section_name, "saml.role_arn")
    region_name = config.get(section_name, "region") if config.has_option(section_name, "region") else region_name

    try:
        sts = boto3.client("sts", config=botocore.config.Config(signature_version=botocore.UNSIGNED))
        response = sts.assume_role_with_saml(
            DurationSeconds=session_duration,
            PrincipalArn=principal_arn,
            RoleArn=role_arn,
            SAMLAssertion=saml,
        )
        if response:
            cred = configparser.RawConfigParser()
            cred.read(cred_path)

            if not cred.has_section(profile_name):
                cred.add_section(profile_name)

            cred.set(profile_name, "aws_access_key_id", response["Credentials"]["AccessKeyId"])
            cred.set(profile_name, "region", region_name) if region_name else cred.remove_option(profile_name, "region")
            cred.set(profile_name, "aws_secret_access_key", response["Credentials"]["SecretAccessKey"])
            cred.set(profile_name, "aws_session_token", response["Credentials"]["SessionToken"])
            # Duplicate aws_session_token to aws_security_token to support legacy AWS clients.
            cred.set(profile_name, "aws_security_token", response["Credentials"]["SessionToken"])
            cred.set(profile_name, "aws_session_expiration", response["Credentials"]["Expiration"].strftime("%Y-%m-%dT%H:%M:%S%z"))

            if write_to_file:
                with open(cred_path, "w+") as f:
                    cred.write(f)
                    print("Credentials saved to file for {}. Expire {}.".format(profile_name, response["Credentials"]["Expiration"]))
            elif export_to_env:
                os.environ['AWS_ACCESS_KEY_ID'] = cred.get(profile_name, "aws_access_key_id")
                os.environ['AWS_SESSION_TOKEN'] = cred.get(profile_name, "aws_session_token")
                os.environ['AWS_SECRET_ACCESS_KEY'] = cred.get(profile_name, "aws_session_token")
                print("Credentials exported to env variables for {}. Expire {}.".format(profile_name, response["Credentials"]["Expiration"]))
            elif print_to_stdout:
                print("AWS_ACCESS_KEY_ID:", cred.get(profile_name, "aws_access_key_id"))
                print("AWS_SESSION_TOKEN:", cred.get(profile_name, "aws_session_token"))
                print("AWS_SECRET_ACCESS_KEY:", cred.get(profile_name, "aws_secret_access_key"))
                print(f"export AWS_ACCESS_KEY_ID=\"{cred.get(profile_name, "aws_access_key_id")}\"", )
                print(f"export AWS_SESSION_TOKEN=\"{cred.get(profile_name, "aws_session_token")}\"")
                print(f"export AWS_SECRET_ACCESS_KEY=\"{cred.get(profile_name, "aws_secret_access_key")}\"")
                print(f"export TF_VAR_aws_access_key_id=\"{cred.get(profile_name, "aws_access_key_id")}\"", )
                print(f"export TF_VAR_aws_secret_access_key=\"{cred.get(profile_name, "aws_session_token")}\"")
                print("Credentials for {}. Expire {}.".format(profile_name, response["Credentials"]["Expiration"]))

            return Saml(aws_access_key_id=cred.get(profile_name, "aws_access_key_id"),
                        aws_session_token=cred.get(profile_name, "aws_session_token"),
                        aws_secret_access_key=cred.get(profile_name, "aws_secret_access_key"))

    except botocore.errorfactory.ClientError as ete:
        print(ete)


def get(saml: str) -> Data:
    root = ET.fromstring(saml)
    _data = Data("", "")

    for item in root.iter(START_LEAF):
        if item.attrib["FriendlyName"] == SESSION_ROLE:

            for item1 in item.iter(SECOND_LEAF):
                _tmp = item1.text.split(",")
                _data = Data(_tmp[0], _tmp[1])

    return _data


def update(pat: str = None, group: str = None, saml: Saml = None):
    gl = gitlab.Gitlab(private_token=pat)
    g = gl.groups.get(gl.groups.list(search=group, get_all=True)[0].id)

    for _p in g.projects.list(get_all=True):
        if _p.name == "sense8":
            print(f"Get group <{group}> project <{_p.name}> object...")
            p = gl.projects.get(_p.id)
            print(f"Get group <{group}> project <{p.name}> object -> Done")

            for variable in AWS_CREDENTIAL_VARS:
                try:
                    print(f"Update variable <{variable}>...")
                    _variable = p.variables.get(variable.upper())
                    _variable.value = getattr(saml, variable)
                    _variable.save()
                    print(f"Update variable <{variable}> -> DONE")
                except (gitlab.exceptions.GitlabHttpError, gitlab.exceptions.GitlabGetError) as err:
                    print(f"Update project <{p.name}> level variable <{variable}> failed with error: {err.error_message}")
                except AttributeError as ae:
                    print(ae)


if __name__ == '__main__':
    print("SAML ROLE_ARN and IDP_ARN extractor")
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="base64 saml response file", type=str)
    parser.add_argument("-s", "--string", help="base64 saml response string", type=str)
    parser.add_argument("-e", "--environment", help="export environment vars", type=bool)
    parser.add_argument("-w", "--write", help="write credentials file", type=bool)
    parser.add_argument("-p", "--print", help="print credentials to stdout", type=bool)
    parser.add_argument("-u", "--update", help="update credentials in gitlab", type=bool)
    parser.add_argument("-a", "--pat", help="Gitlab PAT", type=str)
    args = parser.parse_args()
    data = None
    saml = None

    if args.file:
        with open(args.file, "r") as fp:
            raw = fp.read()
        data = get(base64.b64decode(raw).decode("utf-8"))
        saml = raw

    if args.string:
        data = get(base64.b64decode(args.string).decode("utf-8"))
        saml = args.string

    if data:
        _saml = run(idp_arn=data.idp_arn, role_arn=data.role_arn, saml=saml, write_to_file=args.write, export_to_env=args.environment, print_to_stdout=args.print)

        if args.update:
            update(pat=args.pat, group="regression", saml=_saml)
