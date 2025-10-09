import json
import logging
import pandas as pd
from urllib.parse import urlparse
import io

import boto3
from botocore.exceptions import ClientError, ParamValidationError

# TODO: removing and print statements used for testing

logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG) --> setup in main()/env? --> timestamp?
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

    except ValueError:  # TODO: check
        logging.error("Invalid JSON")
        raise ValueError("Invalid JSON")  #check
    
    if not isinstance(data, dict): 
        logging.warning("JSON should be a dictionary")
        raise ValueError("JSON should be a dictionary")
    
    if len(data) > 2: 
        logging.warning("additional fields present")

    if len(data) < 2: 
        logging.error("insufficient number of fields present")

    # # optional: (if fields are fixed)
    # permitted_keys = ["file_to_obfuscate", "pii_fields"] # TODO: find way to avoid hard coding fields?
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
  
    logging.info("Valid JSON and valid fields")
    return data
#TODO: complete last 2 tests for this

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

    file_details = {"Scheme" : scheme, "Bucket" : bucket, "Key": key, "File_Name": file_name, "File_Type": file_type}

    return file_details

def extract_fields_to_alter(verified_input: dict) -> list: 
    """using the dict from validate_json() return the headings in a list.

    Args:
        verified_input (dict): the dictionary returned from validate_input_json()

    Raises:
        ValueError: if NoneType  # TODO: confirm if keeping this in 
        ValueError: if empty list 
        TypeError: if list contains elements that are not strings

    Returns:
        list: list of the 
    """
    fields = verified_input["pii_fields"] #TODO: check that this being hard coded is acceptable 
    
    #should be handled in validate_json()
    if fields == None: 
        logging.error("no fields present")
        raise ValueError("no fields present")
    
    if not isinstance(fields, list): 
        logging.error("fields must be a list")
        raise TypeError("fields must be a list")

    if len(fields) == 0: 
        logging.error("no fields detected")
        raise ValueError ("no fields detected")

    invalid_fields = []
    for heading in fields: 
        if not isinstance(heading, str):
            invalid_fields.append(heading)
    
    if invalid_fields: 
        logging.error(f"The following headings are not strings: {invalid_fields}")
        raise TypeError (f"The following headings are not strings: {invalid_fields}")
    
    logging.info("pii fields extracted")
    return fields

    # fields valid (headings) vs df -> cannot be handled here? 

def get_file(file_details: dict, s3: object) -> bytes: 
    bucket = file_details["Bucket"]
    key = file_details["Key"]

    try: 
        file_object = s3.get_object(Bucket=bucket, Key=key)  # -> returns dict
        data = file_object['Body'].read()  # .read() to return bytes
        logging.info("file retrieved")
        return data
       
    except ClientError as err:  
        if err.response["Error"]["Code"] == "NoSuchKey":
            logging.error(f"{err.response["Error"]["Code"]} : {err.response["Error"]["Message"]} -> check the file name/path")
        if err.response["Error"]["Code"] == "InvalidObjectState": 
            logging.error(f"{err.response["Error"]["Code"]} : {err.response["Error"]["Message"]} -> file is archived, retrieve before proceeding")
        else: 
            logging.error(f"{err.response["Error"]["Code"]} : {err.response["Error"]["Message"]}")  # eg. NoSuchBucket
        raise err
    
    
    # TODO: check if ParamValidationError exception required

""" alternative"""
def convert_file_to_df(file_details: dict, file_object: bytes): #pass in dict and bytestream from get_file() # TODO: confirm if file_object is bytes or bobysream? 
    try: 
        if file_details["File_Type"] == 'csv': 
            df = pd.read_csv(io.BytesIO(file_object))  # TODO: read up on io.BytesIO - pandas cannor read raw bytes 
        #extension: 
        # if file_type == 'json': 
        #     df = pd.read_json(file_object])
    except pd.errors.EmptyDataError as error:
        logging.error("the file you are trying to retrieve does not contain any data")
        raise error

    return df

def obfuscate_data(data: pd.DataFrame, fields: list) -> bytes:
    # TODO: confirm if returning bytes or df # TODO: use this style for all?
    """obfuscating the values under the headings defined in fields list.

    args:
    data - pd.DataFrame (returned from get_csv())
    fields - list (from JSON passed to obfuscator())

    returns:
    new csv bytes, exact copy of original but with relevant columns obfuscated.
    """
    df = data.copy()

    invalid_headings = []

    for heading in fields:
        valid_columns = list(df.columns)
        if heading not in valid_columns:
            invalid_headings.append(heading)
        # if datatype in specific row/column is not str log a warning
        # TODO: check how to specify specific fields within
        # the pd and put in the warning (cast them safely) eg. 0 or NaN
        else:
            df[heading] = "xxx"
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
    validate_input_json()
    extract_s3_details()
    extract_fields_to_alter()
    get_csv()  # or get_file() if updated
    convert_file_to_df()  # TODO: this where file type is handled? 
    obfuscate_data()
 
    """setup with extension in mind"""

    if file_type == "csv":
        data = get_csv(bucket, file_name, s3)
        obfuscated_df = obfuscate_data(data, fields)
        # new_file_name = f"Obfuscated-{file_name}"
        csv_output = obfuscated_df.to_csv(index=False).encode()
        # encoded to return bytes (cannot have file location else is NoneType)
        return csv_output
    # if file_type == "json":
    else:
        logging.error("invalid document type")
        #raise exception





"""delete?"""
def get_csv(bucket: str, key: str, s3: object) -> pd.DataFrame:
    #TODO: could this be get_file? verify bucket/file exists and extract 
    #would require another function to read file/access the data within
    """access the specified S3 bucket and retrieve the file.

    args:
    bucket - retrieved from json passed to obfuscator()  # TODO: update 
    file_name - retrieved from json passed to obfuscator() # TODO: update 

    returns:
    Pandas DataFrame

    Exceptions:
    Raises ClientError NoSuchKey if file name is not present.
    Raises ClientError InvalidObjectState if file is archived and
        needs to be retored prior to accessing.
    Raises Pandas EmptyDataError if the file being retrieved is empty.
    """
    try:
        csv_file_object = s3.get_object(Bucket=bucket, Key=key)  # -> returns dict
        logging.info("csv file successfully retrieved")
        df = pd.read_csv(csv_file_object["Body"])
        return df

    #added in: (was originally in s3 extraction part/main func)
    except ParamValidationError as error:  # botocore exception
            logging.error("invalid URL")
            raise error

    except pd.errors.EmptyDataError as error:
        logging.error("the file you are trying to retrieve does not contain any data")
        raise error
    except ClientError as error:  
        if error.response["error"]["code"] == "NoSuchKey":
            logging.error("the file does not exist, check filename")
            raise error
        if error.response["error"]["code"] == "InvalidObjectState": 
            logging.warning("Your file is archived, retrieve before proceeding")
            raise error
            # TODO: check error handling here
    # S3.Client.exceptions.NoSuchKey
    # S3.Client.exceptions.InvalidObjectState

    """ extension """  #not necessary? 
    # def get_json(): 
    #     pass 

    # def get_parquet(): 
    #     pass




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
    pass

# TODO: check logging levels: info -> sucess, warning -> recoverable issue, error -> critical failure! 
# TODO: standardise exceptions and logging. raise in helper funcs and log in final func? 