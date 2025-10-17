import json
import logging
import pandas as pd
from urllib.parse import urlparse
import io
import boto3
from botocore.exceptions import ClientError
import time

# TODO: standardise exceptions and logging. raise in helper funcs and log in final func?
# TODO: confirm security, PEP8 compliance.
# TODO: custom exceptions? 

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG) --> setup in main()/env? --> timestamp?
# alter level if needed [debug, info, warning, error, critical]

s3 = boto3.client("s3")


# Helper functions
def validate_input_json(input_json: str) -> dict:
    """validate JSON string and return dict if valid.

    Args:
        input_json: JSON string passed into initial function

    Raises:
        TypeError: if not a JSON string being input
        json.JSONDecodeError: if invalid JSON syntax
        ValueError: if not required output format (dict), 
                    missing required keys, or invalid value types
    
    Returns: 
        dictionary: verified input in dictionary format
    """
    try:
        data = json.loads(input_json)

    # if not valid json string:
    except TypeError as err:
        logging.error(f"invalid JSON: {err}")
        raise

    # invalid json syntax
    except json.JSONDecodeError as err:
        logging.error(f"invalid JSON syntax: {err}")
        raise

    # invalid output format 
    if not isinstance(data, dict):
        logging.error("dictionary format required")
        raise ValueError("dictionary format required")
    
    # missing required output keys 
    expected_keys = ["file_to_obfuscate", "pii_fields"]
    input_keys = list(data.keys())
    missing_keys = []

    for field in expected_keys:
        if field not in input_keys:
            missing_keys.append(field)
    if missing_keys:
        logging.error(f"missing key(s) from json str: {missing_keys}")
        raise ValueError(f"missing key(s) from json str: {missing_keys}")

    # invalid output values format
    if not isinstance(data["file_to_obfuscate"], str):
        logger.error("file_to_obfuscate must have a string value")
        raise ValueError("file_to_obfuscate must have a string value")
    
    if not isinstance(data["pii_fields"], list): 
        logger.error("pii_fields must contain a list")
        raise ValueError("pii_fields must contain a list")

    # valid output
    verified_input = data
    logging.info("Valid JSON and valid fields")
    return verified_input

def extract_file_location_details(verified_input: dict) -> dict:
    """Returns dict with all file and location details.

    Args:
        verified_input (dict): dictionary output from validate_input_json()

    Raises:
        ValueError: if empty string - no URL present
        ValueError: if URL does not contain s3 scheme - not valid for s3
        ValueError: if file_name/type not identified
        ValueError: if file_type is not listed as permitted 

    Returns:
        dict: containing all details relating the the file and location
    """
    permitted_file_types = ["csv", "json"]  # update here for extension

    url = verified_input["file_to_obfuscate"]
    
    o = urlparse(url)

    scheme = o.scheme
    bucket = o.netloc
    key = o.path.lstrip("/")  # file_path/file_name (with first / removed)
    file_name = key.split("/")[-1]
    file_type = file_name.split(".")[-1]

    if len(url) == 0:
        logging.error("no URL")
        raise ValueError("no URL")

    if scheme != "s3":
        logging.error("not a valid s3 URL")
        raise ValueError("not a valid s3 URL")

    if not file_name or "." not in file_name:
        file_type = None
        logging.error("unable to confirm file type")
        raise ValueError("unable to confirm file type")

    if file_type not in permitted_file_types:
        logging.error(f"unable to process {file_type} files")
        raise ValueError(f"unable to process {file_type} files")

    file_details = {
        "Scheme": scheme,
        "Bucket": bucket,
        "Key": key,
        "File_Name": file_name,
        "File_Type": file_type,
    }

    return file_details

def extract_fields_to_alter(verified_input: dict[str, list[str]]) -> list[str]:
    """Returns list of the column headings to be obfuscated. 

    Args:
        verified_input (dict): output from validate_input_json() 

    Raises:
        ValueError: if empty list
        TypeError: if list elements are not strings

    Returns:
        list: list of fields to be obfuscated
    """
    fields = verified_input["pii_fields"]

    if len(fields) == 0:
        logging.error("no fields to obfuscate provided")
        raise ValueError("no fields to obfuscate provided")

    invalid_fields = [heading for heading in fields if not isinstance(heading, str)]

    if invalid_fields:
        logging.error(f"The headings : {invalid_fields} are not strings")
        raise TypeError(f"The headings : {invalid_fields} are not strings")

    logging.info("pii fields extracted")
    return fields

def get_file(file_details: dict[str, str], s3: boto3.client) -> bytes:
    """Retrieves file from s3 bucket provided in file details.

    Args:
        file_details (dict): output dict from extract_file_location_details()
        s3 (object): boto3 s3 client

    Raises:
        ClientError:
            'NoSuchBucket' - bucket does not exist/incorrect bucket name
            'NoSuchKey' - file name/path does not exist/ incorrect naming
            'InvalidObjectState' - file is archived, retrieve before proceeding

    Returns:
        bytes: returns bytestream of extracted file 
    """
    bucket = file_details["Bucket"]
    key = file_details["Key"]

    try:
        file_object = s3.get_object(
            Bucket=bucket, Key=key
        )  # returns dict -> ["Body"]=streaming object
        data_body = file_object["Body"]  # can only be read once
        data_bytes = data_body.read()  # .read() returns bytes (reusable)
        logging.info("file retrieved")
        return data_bytes

    except ClientError as err:
        error_code = err.response["Error"]["Code"]
        error_msg = err.response["Error"]["Message"]

        logging.error(f"for s3://{bucket}/{key} -> {error_code} : {error_msg}")
        raise err

def convert_file_to_df(file_details: dict[str, str], data: bytes) -> pd.DataFrame:
    """Converts bytestream data to pd.Dataframe

    Args:
        file_details (dict): output dict from extract_file_location_details()
        data (bytes): bytes returned from get_file()

    Raises:
        pd.errors.EmptyDataError: if file is empty

    Returns:
        pd.DataFrame: return pandas DataFrame
    """

    file_type = file_details["File_Type"]
    file_name = file_details["File_Name"]
    bucket = file_details["Bucket"]

    try:
        if file_type == "csv":
            data_stream = io.BytesIO(data)  # convert bytes to in memory file-like object stream
            df = pd.read_csv(data_stream, on_bad_lines='error')   # pd expects file-like object, 
                                            # can read from stream (not bytes)

        """extension:"""
        # if file_type == 'json':
        #     data_object = io.BytesIO(data)
        #     df = pd.read_json(data_object)

    except pd.errors.EmptyDataError as error:
        logging.error(f"the file: {file_name} from: {bucket} is empty")
        raise error

    return df


def obfuscate_data(data_df: pd.DataFrame, fields: list) -> pd.DataFrame:
    """obfuscating the values under the headings defined in fields list.

    args:
    data_df - pd.DataFrame returned from convert_file_to_df()
    fields  - list returned from extract_fields_to_alter()

    returns:
    new DataFrame, exact copy of original but with relevant columns obfuscated.
    """
    df = data_df.copy()

    invalid_headings = []

    for heading in fields:
        valid_columns = list(df.columns)
        if heading not in valid_columns:
            invalid_headings.append(heading)
        else:
            df[heading] = "xxx"

    if invalid_headings:
        logger.warning(f"The Heading : {invalid_headings} does not exist")

    """Additional warning possible"""
    # missing_row = df.index[df.isna().any(axis=1)] #  1 = column   --> df removes empty lines by default? 
    # logger.warning(f"Data missing in the following index locations: {missing_row}")

    return df


def convert_obf_df_to_bytestream(obs_df: pd.DataFrame, file_details: dict) -> bytes:
    """converts obfuscated bystream back to bystream
        (compatible with s3 put_object)

    args:
        obs_df (pd.DataFrame) : returned from obfuscate_data()
        file_details (dict) : output dict from extract_file_location_details()

    returns:
        bytestream containing file content
    """
    file_type = file_details["File_Type"]
    # file_name = file_details[ "File_Name"] #for local testing only

    if file_type == "csv":
        buffer = io.BytesIO()  # write to buffer rather than locally
        obs_df.to_csv(buffer, index=False)
        output_bytestream = buffer.getvalue()

        """for local testing only"""
        # output_file = obs_df.to_csv(f'obf_{file_name}.csv', index=False)

    """extension"""
    # if file_type == "json":
    #     output_bytestream = obs_df.to_json(index=False)

    logging.info("obfuscated file ready")
    return output_bytestream


# Primary function
def obfuscator(input_json: str) -> bytes:  # TODO: output object ??
    """produces a copy of the file data with the specified columns obsuscated
        so sensitive information remains anonymous.

    args:
        JSON string containing:
        - file to obfuscate - s3 URL locating the required file for obfuscation
        - pii fields - names of the fields that are required to be obfuscated

    returns:
        bytestream containing an exact copy of the input file but with
        the specified sensitive data replaced with obfuscated string
    """

    verified_input = validate_input_json(input_json)
    file_details = extract_file_location_details(verified_input)
    fields = extract_fields_to_alter(verified_input)
    data = get_file(file_details, s3)
    data_df = convert_file_to_df(file_details, data)
    obf_df = obfuscate_data(data_df, fields)
    file_output = convert_obf_df_to_bytestream(obf_df, file_details)
    return file_output


if __name__ == "__main__":
    # get_csv(bucket='tr-nc-test-source-files',
    #         key='Titanic-Dataset.csv',
    #         s3=s3)

    # data = get_csv(bucket='tr-nc-test-source-files',
    #                key='Titanic-Dataset.csv',
    #                s3=s3)
    # fields = ["Name", "Sex", "Age"]
    # obfuscate_data(data, fields)

    # obfuscator(json.dumps({"file_to_obfuscate": "",
    #    "pii_fields": ["Name", "Sex", "Age"]}))
    # "s3://tr-nc-test-source-files/Titanic-Dataset.csv"

    """run on cli"""
    # #correct version:
    obfuscator(
        (
            '{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv",'
            '"pii_fields": ["Name", "Sex", "Age"]}'
        )
    )

    # #no fields to obfuscate:
    # obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": []}')

    # #no file extension
    # obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset", "pii_fields": ["Name", "Sex", "Age"]}')

    # #invalid json
    # obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": }')

    # Incorrect URL
    # obfuscator('{"file_to_obfuscate": "://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": ["Name", "Sex", "Age"]}')
    # obfuscator('{"file_to_obfuscate": "s3://nc-tr-test-source-files/Titanic-Dataset.csv", "pii_fields": ["Name", "Sex", "Age"]}')
