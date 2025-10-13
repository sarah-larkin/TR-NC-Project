import json
import logging
import pandas as pd
from urllib.parse import urlparse
import io

import boto3
from botocore.exceptions import ClientError

# TODO: standardise exceptions and logging. raise in helper funcs and log in final func?
# TODO: use single quotes in f strings 
# TODO: use () for long strings 

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG) --> setup in main()/env? --> timestamp?
# alter level if needed [debug, info, warning, error, critical]

s3 = boto3.client("s3")

# Helper functions
def validate_input_json(input_json: str) -> dict:
    """validate JSON string and return parsed dict if valid.

    Args:
        input_json: json string passed into initial function

    Raises:
        ValueERror: Invalid JSON string
    """
    try:
        data = json.loads(input_json)

    #if not valid json string: 
    except TypeError as err: 
        logging.warning (f'Invalid JSON: {err}')
        raise
    
    #invalid json syntax 
    except json.JSONDecodeError as err: 
        logging.warning(f"Invalid JSON syntax: {err}")
        raise ValueError(f"{err}")      #TODO: check 

    except ValueError as err:  # TODO: check ValueError twice?? 
        logging.warning("Invalid JSON: {err}")
        raise 

    if not isinstance(data, dict):
        logging.warning("JSON should be a dictionary")
        raise ValueError

    if len(data) > 2:
        logging.warning("additional key(s) present")

    if len(data) < 2:
        logging.warning("insufficient number of keys present")

    # # optional: (if keys are fixed)
    # permitted_keys = ["file_to_obfuscate", "pii_fields"]

    # keys = list(data.keys())
    # incorrect_keys = []
    # missing_keys = []

    # for field in keys:
    #     if field not in permitted_keys:
    #         incorrect_keys.append(field)
    # if incorrect_keys:
    #     logging.warning(f"Fields that are not permitted: {incorrect_keys}")
    #     raise ValueError(f"Fields that are not permitted: {incorrect_keys}")

    # for field in permitted_keys:
    #     if field not in keys:
    #         missing_keys.append(field)
    # if missing_keys:
    #     logging.warning(f"Missing Fields: {missing_keys}")
    #     raise ValueError(f"Missing Fields: {missing_keys}")

    verified_input = data 
    logging.info("Valid JSON and valid fields")
    return verified_input


    # TODO: complete last 2 tests for this

def extract_s3_details(verified_input: dict) -> dict:

    url = verified_input["file_to_obfuscate"]
    o = urlparse(url)

    scheme = o.scheme
    bucket = o.netloc
    key = o.path.lstrip("/")  # file_path/file_name (with first / removed)
    file_name = key.split("/")[-1]
    file_type = file_name.split(".")[-1]

    permitted_file_types = ["csv"]  # TODO: update in extension

    if len(url) == 0:
        logging.error("no URL")
        raise ValueError("no URL")

    if scheme != "s3":
        logging.error("not a valid s3 URL")
        raise ValueError("not a valid s3 URL")

    # TODO: check if this is engough to verify the URL

    if not file_name or "." not in file_name:
        logging.error("unable to confirm file type")
        file_type = None
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

def extract_fields_to_alter(verified_input: dict) -> list:
    """using the dict from validate_json() return the headings in a list.

    Args:
        verified_input (dict):
        dictionary returned from validate_input_json()

    Raises:
        ValueError: if NoneType  # TODO: confirm if keeping this in
        ValueError: if empty list
        TypeError: if list contains elements that are not strings

    Returns:
        list: list of the
    """
    fields = verified_input["pii_fields"]

    if fields is None:
        logging.error("fields to obfuscate : None")
        raise ValueError("fields to obfuscate : None")

    if len(fields) == 0:
        logging.error("no fields to obfuscate provided")
        raise ValueError("no fields to obfuscate provided")
    
    if not isinstance(fields, list):
        logging.error("fields must be a list")
        raise TypeError("fields must be a list")

    invalid_fields = []
    for heading in fields:
        if not isinstance(heading, str):
            invalid_fields.append(heading)

    if invalid_fields:
        logging.error(
            f"The following headings are not strings: {invalid_fields}")
        raise TypeError(
            f"The following headings are not strings: {invalid_fields}")

    logging.info("pii fields extracted")
    return fields

    # fields valid (headings) vs df -> cannot be handled here?

def get_file(file_details: dict, s3: object) -> bytes:
    """takes dict from extract_s3_details() and retrieves named file from named s3 bucket

    Args:
        file_details (dict): output dict from extract_s3_details()
        s3 (object): boto3 s3 client 

    Raises:
        ClientError:"NoSuchBucket" - bucket does not exist/incorrect bucket name 
                    "NoSuchKey" - file name/path does not exist/ incorrect naming 
                    "InvalidObjectState" - file is archived and needs to be retrieved first

    Returns:
        bytes: returns bytes object ready to be converted to DataFrame in convert_file_to_df()
    """
    bucket = file_details["Bucket"]
    key = file_details["Key"]

    try:
        file_object = s3.get_object(Bucket=bucket, Key=key)  # returns dict
        data = file_object["Body"].read()  # .read() to return bytes
        logging.info("file retrieved")
        return data

    except ClientError as err:
        error_code = err.response["Error"]["Code"]
        error_msg = err.response["Error"]["Message"]

        logging.error(f"for s3://{bucket}/{key} -> {error_code} : {error_msg}")
        raise err
     

def convert_file_to_df(
    file_details: dict, data: bytes
) -> (
    pd.DataFrame
):  
    """_takes raw bytes from get_file() and converts to pd.Dataframe

    Args:
        file_details (dict): dictionary returned from extract_s3_details()
        file_object (bytes): bytes returned from get_file()

    Raises:
        error: _description_  # TODO: complete 

    Returns:
        pd.DataFrame: return pandas DataFrame
    """
    try:
        if file_details["File_Type"] == "csv":
            df = pd.read_csv(
                io.BytesIO(data)
            )  # TODO: read up on io.BytesIO - pandas cannot read raw bytes
        # extension:
        # if file_type == 'json':
        #     df = pd.read_json(io.BytesIO(data))
    except pd.errors.EmptyDataError as error:
        logging.error(
            "the file you are trying to retrieve does not contain any data")
        raise error

    return df
    # TODO: check exception raising - filetype 

def obfuscate_data(data_df: pd.DataFrame, fields: list) -> pd.DataFrame:
    # TODO: confirm if returning bytes or df
    #if bytest pass in dict got get file type? then to_csv().encode()??? 
    """obfuscating the values under the headings defined in fields list.

    args:
    data_df - pd.DataFrame returned from convert_file_to_df()
    fields - list returned from extract_fields_to_alter()

    returns:
    new DataFrame, exact copy of original but with relevant columns obfuscated.
    """
    df = data_df.copy()

    invalid_headings = []

    for heading in fields:
        valid_columns = list(df.columns)
        if heading not in valid_columns:
            invalid_headings.append(heading)
        # if datatype in specific row/column is not str log a warning (giving primary key/location?)
        # TODO: check how to specify specific fields within
        # the pd and put in the warning (cast them safely) eg. 0 or NaN
        else:
            df[heading] = "xxx"
    if invalid_headings:
        logger.warning(f"Invalid headings identified: {invalid_headings}") 
    return df

# Primary function
def obfuscator(input_json: json) -> bytes:
    """
    function summary:
    produce a copy of the csv file specified in the input_json
    (location of file/pii fields to obfuscate) with the specified
    columns obsuscated so sensitive information remains anonymous.

    args:
    JSON string containing:
    - file to obfuscate - S3 location of the required CSV file for obfuscation
    - pii fields - names of the fields that are required to be obfuscated

    returns:
    new byte string object containing an exact copy of the input file but with
    the specified sensitive data replaced with obfuscated string
    (boto3 put_object compatible).
    (Calling procedure will handle saving returned bytes from this function)

    exceptions: # TODO: list exceptions
    """
    # TODO: update function to incorporate all helper funcs and return bytes
    verified_input = validate_input_json(input_json)
    file_details = extract_s3_details(verified_input)
    fields = extract_fields_to_alter(verified_input)
    data = get_file(file_details, s3)
    data_df = convert_file_to_df(file_details, data)  # TODO: this where file type is handled?
    obf_df = obfuscate_data(data_df, fields)
    print(obf_df)
    return obf_df




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

    # TODO: confirm security, PEP8 compliance.
    
    """run on cli"""
    # #correct version:
    obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": ["Name", "Sex", "Age"]}')

    # #no fields to obfuscate:
    # obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": []}')

    # #no file extension
    # obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset", "pii_fields": ["Name", "Sex", "Age"]}')
  
    # #invalid json
    # obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": }')

    #Incorrect URL
    #obfuscator('{"file_to_obfuscate": "://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": ["Name", "Sex", "Age"]}')
    #obfuscator('{"file_to_obfuscate": "s3://nc-tr-test-source-files/Titanic-Dataset.csv", "pii_fields": ["Name", "Sex", "Age"]}')