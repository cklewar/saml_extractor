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

START_LEAF = "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
SECOND_LEAF = "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
SESSION_ROLE = "Session Role"
AWS_DEFAULT_CONFIG_PATH = "~/.aws/config"
AWS_DEFAULT_CREDENTIALS_PATH = "~/.aws/credentials"
SAML_DEFAULT_SESSION_DURATION = 43200
Data = namedtuple("Data", "role_arn idp_arn")


def run(profile=None, region: str = None, session_duration: int = None, idp_arn: str = None, role_arn: str = None, saml: str = None, write_to_file: bool = False, export_to_env: bool = False):
    profile_name = profile or os.environ.get("AWS_PROFILE", "default")
    region_name = region or os.environ.get("AWS_DEFAULT_REGION", None)
    section_name = (profile_name if profile_name == "default" else f"profile {profile_name}")
    config_path = os.environ.get("AWS_CONFIG_FILE") or os.path.expanduser(AWS_DEFAULT_CONFIG_PATH)
    cred_path = os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or os.path.expanduser(AWS_DEFAULT_CREDENTIALS_PATH)

    config = configparser.RawConfigParser()
    config.read(config_path)

    try:
        session_duration = session_duration or config.getint(section_name, "saml.session_duration")
    except configparser.NoOptionError:
        session_duration = SAML_DEFAULT_SESSION_DURATION

    principal_arn = idp_arn or config.get(section_name, "saml.idp_arn")
    role_arn = role_arn or config.get(section_name, "saml.role_arn")

    try:
        print("CFG:", config)
        print("REGION_NAME:", region_name)
        print("REGION_NAME_CFG:", config.get(section_name, "region"))
        region_name = region_name or config.get(section_name, "region")
    except configparser.NoOptionError:
        pass

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
            if region_name is not None:
                cred.set(profile_name, "region", region_name)
            else:
                cred.remove_option(profile_name, "region")

            cred.set(profile_name, "aws_secret_access_key", response["Credentials"]["SecretAccessKey"])
            cred.set(profile_name, "aws_session_token", response["Credentials"]["SessionToken"])
            # Duplicate aws_session_token to aws_security_token to support legacy AWS clients.
            cred.set(profile_name, "aws_security_token", response["Credentials"]["SessionToken"])
            cred.set(profile_name, "aws_session_expiration", response["Credentials"]["Expiration"].strftime("%Y-%m-%dT%H:%M:%S%z"))

            if write_to_file:
                with open(cred_path, "w+") as f:
                    cred.write(f)
                    print("Credentials saved for {}. Expire {}.".format(profile_name, response["Credentials"]["Expiration"]))
            elif export_to_env:
                os.environ['AWS_ACCESS_KEY_ID'] = cred.get(profile_name, "aws_access_key_id")
                os.environ['AWS_SESSION_TOKEN'] = cred.get(profile_name, "aws_session_token")
                os.environ['AWS_SECRET_ACCESS_KEY'] = cred.get(profile_name, "aws_session_token")
                print("AWS_ACCESS_KEY_ID:", os.getenv("AWS_ACCESS_KEY_ID"))
                print("AWS_SESSION_TOKEN:", os.getenv("AWS_SESSION_TOKEN"))
                print("AWS_SECRET_ACCESS_KEY:", os.getenv("AWS_SECRET_ACCESS_KEY"))
                print("Credentials exported for {}. Expire {}.".format(profile_name, response["Credentials"]["Expiration"]))

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


if __name__ == '__main__':
    print("SAMl ROLE_ARN and IDP_ARN extractor")
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="base64 saml response file", type=str)
    parser.add_argument("-s", "--string", help="base64 saml response string", type=str)
    parser.add_argument("-e", "--environment", help="export environment vars", type=bool)
    parser.add_argument("-w", "--write", help="write credentials file", type=bool)
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as fp:
            raw = fp.read()
        data = get(base64.b64decode(raw).decode("utf-8"))
        run(idp_arn=data.idp_arn, role_arn=data.role_arn, session_duration=43200, saml=raw, export_to_env=args.environment, write_to_file=args.write)

    if args.string:
        data = get(base64.b64decode(args.string).decode("utf-8"))
        run(idp_arn=data.idp_arn, role_arn=data.role_arn, session_duration=43200, saml=args.string, export_to_env=args.environment, write_to_file=args.write)
