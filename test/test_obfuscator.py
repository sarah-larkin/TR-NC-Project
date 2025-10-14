from obfuscator.obfuscator import (
    validate_input_json,
    extract_s3_details,
    extract_fields_to_alter,
    get_file,
    convert_file_to_df,
    obfuscate_data,
    convert_obf_df_to_file,
    obfuscator,
)
import pytest
import pandas as pd
from botocore.exceptions import ClientError
from copy import deepcopy
import numpy as np
import logging
from moto import mock_aws
from unittest.mock import patch

# TODO: check out pytest.mark.parametrize 
# TODO: remove repetative tests 
# TODO: combine logging and raising tests 

class TestValidateJSON:
    def test_validate_json_returns_dict_if_json_valid(
            self,
            mock_input_json_for_csv_file,
            caplog
        ):
        caplog.set_level(logging.INFO)
        result = validate_input_json(mock_input_json_for_csv_file)
        assert result == {
            "file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",
            "pii_fields": ["Name", "Email", "Phone", "DOB"],
        }
        assert "Valid JSON and valid fields" in caplog.text   

    def test_TypeError_raised_if_invalid_json_string(self, caplog): 
        caplog.set_level(logging.WARNING)
        with pytest.raises(TypeError): 
            #dict not json
            validate_input_json({"file_to_obfuscate": "s3://tr-nc-test-source-files/Titanic-Dataset.csv", "pii_fields": ["Name", "Sex", "Age"]})
        assert "Invalid JSON: the JSON object must be str, bytes or bytearray, not dict" in caplog.text

    def test_JSONDecodeError_raised_when_json_invalid(self, caplog): #TODO: check!!
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):  # has to be with pytest.raises
            validate_input_json(
                '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"],}'
            )
            # additional comma, 
            # (no closing bracket)
            assert "Invalid JSON:" in caplog.text

    # TODO: add in test raises valueerror if valid JSON but not a dict 

    def test_2_key_value_pairs_are_passed(self, mock_input_json_for_csv_file):
        result = validate_input_json(mock_input_json_for_csv_file)
        assert len(result) == 2

    def test_warning_logged_if_dict_contains_additional_keys(self, caplog):
        caplog.set_level(logging.WARNING)
        validate_input_json(
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv", '
            '"pii_fields": ["Name", "Email", "Phone", "DOB"],'
            '"additional_key": ["other", "info"]}'
        )
        assert "additional key(s) present" in caplog.text

    def test_warning_logged_if_dict_contians_less_than_two_keys(self, caplog):
        caplog.set_level(logging.WARNING)
        input_json = '{"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        validate_input_json(input_json)
        assert "insufficient number of keys present" in caplog.text

    # TODO: hardcoding ok?
    def test_json_str_contains_specific_keys(self, mock_input_json_for_csv_file):
        """checks specific key names"""
        result = validate_input_json(mock_input_json_for_csv_file)
        key_names = result.keys()
        assert list(key_names) == ["file_to_obfuscate", "pii_fields"]
   
    @pytest.mark.skip
    def test_error_raised_if_different_keys_do_not_match(self, caplog):
        caplog.set_level(logging.WARNING)
        # with pytest.raises(ValueError):
        validate_input_json(
            '{"file": "s3://test_bucket_TR_NC/test_file.csv",'
            '"fields": ["Name", "Email", "Phone", "DOB"]}'
        )

        expected_msg = "Fields that are not permitted: ['file','fields']"
        assert expected_msg in caplog.text

    @pytest.mark.skip
    def test_error_raised_if_required_keys_are_not_present(self, caplog):
        caplog.set_level(logging.WARNING)
        input_json = '{"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        validate_input_json(input_json)
        assert "Missing Fields: ['file_to_obfuscate']" in caplog.text


class TestExtractS3Details:
    def test_s3_details_returns_dict(self, mock_dict_for_csv_file):
        result = extract_s3_details(mock_dict_for_csv_file)
        assert isinstance(result, dict)
        assert result == {
            "Scheme": "s3",
            "Bucket": "test_bucket_TR_NC",
            "Key": "test_file.csv",
            "File_Name": "test_file.csv",
            "File_Type": "csv",
        }

    def test_func_accepts_longer_file_path(self):
        file_path = (
            "s3://test_bucket_TR_NC/"
            "outer_folder/inner_folder/test_file.csv"
        )
        result = extract_s3_details(
            {
                "file_to_obfuscate": file_path,
                "pii_fields": ["Name", "Email", "Phone", "DOB"],
            }
        )
        assert result == {
            "Scheme": "s3",
            "Bucket": "test_bucket_TR_NC",
            "Key": "outer_folder/inner_folder/test_file.csv",
            "File_Name": "test_file.csv",
            "File_Type": "csv",
        }

    # should already be handled in validate_json()
    def test_raises_error_if_URL_null(self):
        with pytest.raises(TypeError):
            extract_s3_details(
                {
                    "file_to_obfuscate": None,
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )

    def test_raises_and_logs_error_if_URL_is_empty_string(self, caplog):
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):
            extract_s3_details(
                {
                    "file_to_obfuscate": "",
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )
        assert "no URL" in caplog.text      

    def test_raises_and_logs_error_if_not_valid_s3_url(self, caplog):
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):
            extract_s3_details(
                {
                    "file_to_obfuscate": "test_bucket_TR_NC/test_file.csv",
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )
            # missing s3://
            assert "not a valid s3 URL" in caplog.text       

    def test_url_raises_and_logs_error_invalid_file_type(self, caplog):
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):
            extract_s3_details(
                {
                    "file_to_obfuscate": "s3://test_bucket_TR_NC/test_file",
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )
            # no file extension
        assert "unable to confirm file type" in caplog.text

    def test_raises_and_logs_error_if_not_accepted_file_type(self, caplog):
        caplog.set_level(logging.ERROR)
        file_path = "s3://test_bucket_TR_NC/test_file.pdf"
        with pytest.raises(ValueError):
            extract_s3_details(
                {
                    "file_to_obfuscate": file_path,
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )
        assert "unable to process pdf files" in caplog.text


class TestExtractFieldsToAlter:
    def test_correct_input_logs_success_msg(
            self,
            caplog,
            mock_dict_for_csv_file):
        caplog.set_level(logging.INFO)
        extract_fields_to_alter(mock_dict_for_csv_file)
        assert "pii fields extracted" in caplog.text

    # should be handled in validate_json() # TODO: confirm if required 
    def test_raises_and_logs_error_if_PII_is_none(self, caplog):
        caplog.set_level(logging.ERROR)
        file_path = "s3://test_bucket_TR_NC/test_file.csv"
        with pytest.raises(ValueError):
            extract_fields_to_alter(
                {
                    "file_to_obfuscate": file_path,
                    "pii_fields": None,
                }
            )
        assert "fields to obfuscate : None" in caplog.text

    def test_logs_and_raises_error_if_fields_list_empty(self, caplog):
        caplog.set_level(logging.ERROR)
        file_path = "s3://test_bucket_TR_NC/test_file.csv"
        with pytest.raises(ValueError):
            extract_fields_to_alter(
                {
                    "file_to_obfuscate": file_path,
                    "pii_fields": [],
                }
            )
        assert "no fields to obfuscate provided" in caplog.text

    def test_error_raised_and_logged_if_fields_is_not_list(self, caplog):
        caplog.set_level(logging.ERROR)
        file_path = "s3://test_bucket_TR_NC/test_file.csv"
        with pytest.raises(TypeError):
            extract_fields_to_alter(
                {
                    "file_to_obfuscate": file_path,
                    "pii_fields": "1, 2, 3",
                }
            )
        assert "fields must be a list" in caplog.text

    

    def test_raises_and_logs_error_if_invalid_fields(self, caplog):
        caplog.set_level(logging.ERROR)
        file_path = "s3://test_bucket_TR_NC/test_file.csv"
        with pytest.raises(TypeError):
            extract_fields_to_alter(
                {
                    "file_to_obfuscate": file_path,
                    "pii_fields": [1, 2, 3, "pii_fields"],
                }
            )
        expected_msg = "The following headings are not strings: [1, 2, 3]"
        assert expected_msg in caplog.text

@mock_aws
class TestGetFile:
    def test_get_file_returns_bytestream(
        self,
        mock_csv_file_details,
        mock_s3_client
    ):
        result = get_file(mock_csv_file_details, mock_s3_client)
        assert isinstance(result, bytes)

    def test_get_file_logs_success_msg(
        self, mock_csv_file_details, mock_s3_client, caplog
    ):
        caplog.set_level(logging.INFO)
        get_file(mock_csv_file_details, mock_s3_client)
        assert "file retrieved" in caplog.text

    # TODO: how to get this passing AND PEP8 compliant? 
    def test_get_file_return_content_of_csv_file(
        self, mock_csv_file_details, mock_s3_client
    ):
        output = get_file(mock_csv_file_details, mock_s3_client)
        expected = b'Name,Email,Phone,DOB,Notes\nAlice,alice@example.com,+1-555-111-2222,1990-01-01,ok\nBob,bob_at_example.com,5551113333,1985-02-03\nCharlie,charlie@ex.co.uk,0,01/05/1975,no action'
        assert output == expected

    # should not be receiving invalid URL so test removed.
    # TODO: check if ParamValidationError should be handled

    def test_get_file_raises_and_logs_ClientError_if_bucket_does_not_exist(
            self,
            mock_s3_client,
            caplog
    ):
        # no buckets created
        test_file_details = {
            "Scheme": "s3",
            "Bucket": "test_bucket_does_not_exist",
            "Key": "test_file.csv",
            "File_Name": "test_file.csv",
            "File_Type": "csv",
        }

        with pytest.raises(ClientError):
            get_file(test_file_details, mock_s3_client)
        expected_msg = "for s3://test_bucket_does_not_exist/test_file.csv -> NoSuchBucket : The specified bucket does not exist"
        assert expected_msg in caplog.text

    def test_get_file_raises_ClientError_with_log_when_file_does_not_exist(
        self,
        mock_s3_client,
        mock_csv_file_details, 
        caplog
    ):
        valid_bucket = mock_csv_file_details["Bucket"]

        mock_file_details = {
            "Scheme": "s3",
            "Bucket": valid_bucket,
            "Key": "WRONG_file.csv",  # file does not exist in mock bucket
            "File_Name": "WRONG_file.csv",
            "File_Type": "csv",
        }
        with pytest.raises(ClientError):
            get_file(mock_file_details, mock_s3_client)
        expected_msg = "for s3://test_bucket_TR_NC/WRONG_file.csv -> NoSuchKey : The specified key does not exist."
        assert expected_msg in caplog.text

    # empty file will be handled in convert_to_df() so removed from here
    
    # TODO: check error handling for archived files? 
    # TODO: check error handling for access issues? is this necessary for library module? (would need patch in testing)


class TestConvertFileToDFFromCSV:
    def test_convert_to_df_returns_df(
            self,
            mock_csv_file_details,
            mock_s3_client
    ):
        file_object = get_file(mock_csv_file_details, mock_s3_client)
        result = convert_file_to_df(mock_csv_file_details, file_object)  #
        assert isinstance(result, pd.DataFrame)

    def test_returns_content_from_the_named_csv_file(
        self, mock_csv_file_details, mock_s3_client
    ):
        file_object = get_file(mock_csv_file_details, mock_s3_client)
        df = convert_file_to_df(mock_csv_file_details, file_object)

        assert list(df.columns) == ["Name", "Email", "Phone", "DOB", "Notes"]
        # df.keys() also works
        assert list(df.loc[0]) == [
            "Alice",
            "alice@example.com",
            "+1-555-111-2222",
            "1990-01-01",
            "ok",
        ]
        assert list(df.loc[1]) == [
            "Bob",
            "bob_at_example.com",
            "5551113333",
            "1985-02-03",
            np.nan,
        ]
        assert list(df.loc[2]) == [
            "Charlie",
            "charlie@ex.co.uk",
            "0",
            "01/05/1975",
            "no action",
        ]

    def test_raises_and_logs_error_if_csv_file_is_empty(
            self,
            mock_bucket,
            mock_s3_client, 
            caplog
    ):
        caplog.set_level(logging.ERROR)

        # empty file:
        mock_s3_client.put_object(
            Bucket=mock_bucket,
            Key="empty_file.csv",
            Body=b""
            )

        mock_file_details = {
            "Scheme": "s3",
            "Bucket": mock_bucket,
            "Key": "empty_file.csv",
            "File_Name": "empty_file.csv",
            "File_Type": "csv",
        }

        file_object = get_file(mock_file_details, mock_s3_client)

        with pytest.raises(pd.errors.EmptyDataError):
            convert_file_to_df(mock_file_details, file_object)
        assert (
            "the file: empty_file.csv from: test_bucket_TR_NC is empty"
            in caplog.text
        )


    @pytest.mark.skip
    def test_error_raised_if_file_invalid(self): 
        #eg. csv with no headers (malformed)
        pass

    @pytest.mark.skip
    def test_raises_Error_if_file_type_inconsistent(self): 
        #eg. .json but content is csv 
        pass


class TestConvertFileToDFFromJSON:
     def test_returns_content_from_the_named_json_file(
        self, mock_json_file_details, mock_s3_client
    ):
        file_object = get_file(mock_json_file_details, mock_s3_client)
        df = convert_file_to_df(mock_json_file_details, file_object)

        assert list(df.columns) == ["Name", "Email", "Phone", "DOB", "Notes"]
        assert list(df.loc[0]) == [
            "Alice",
            "alice@example.com",
            "+1-555-111-2222",
            "1990-01-01",
            "ok",
        ]
        assert list(df.loc[1]) == [
            "Bob",
            "bob_at_example.com",
            "5551113333",
            "1985-02-03",
            None,  #TODO: check why None not np.nan
        ]
        assert list(df.loc[2]) == [
            "Charlie",
            "charlie@ex.co.uk",
            "0",
            "01/05/1975",
            "no action",
        ]


class TestObfuscateData:
    """fields: ["Name", "Email", "Phone", "DOB", "Notes"]"""
    # TODO: delete when done

    def test_new_object_returned(self, mock_df):
        """testing purity - checking new obejct is return"""
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        assert result is not mock_df

    def test_original_data_is_not_mutated(self, mock_df):
        """testing purity - checking original data has not been mutated"""
        copy_of_original = deepcopy(mock_df)
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        pd.testing.assert_frame_equal(mock_df, copy_of_original)

    def test_sensitive_data_is_replaced_by_xxx_in_one_column(self, mock_df):
        result = obfuscate_data(mock_df, ["Email"])
        assert isinstance(result, pd.DataFrame)
        assert list(result.loc[0]) == [
            "Alice",
            "xxx",
            "+1-555-111-2222",
            "1990-01-01",
            "ok",
        ]
        assert list(result.loc[1]) == [
            "Bob",
            "xxx",
            "5551113333",
            "1985-02-03",
            ""
        ]
        assert list(result.loc[7]) == [
            "Eve",
            "xxx",
            "(555) 999-0000",
            "1999-09-09",
            "final row",
        ]

    def test_sensitive_data_is_replaced_by_xxx_in_multiple_columns(
            self,
            mock_df
    ):
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        assert list(result.loc[0]) == ["Alice", "xxx", "xxx", "xxx", "ok"]
        assert list(result.loc[1]) == ["Bob", "xxx", "xxx", "xxx", ""]
        assert list(result.loc[7]) == ["Eve", "xxx", "xxx", "xxx", "final row"]

    #this handled already in other function?? 
    def test_logs_error_msg_if_column_does_not_exist(self, mock_df, caplog):
        caplog.set_level(logging.WARNING)
        result = obfuscate_data(mock_df, ["Address"])
        assert "Invalid headings identified: ['Address']" in caplog.text

    def test_will_still_obfuscate_data_when_datatype_is_not_str(self, mock_df):
        result = obfuscate_data(mock_df, ["Name", "Email", "Phone", "DOB"])
        assert list(result.loc[2]) == ["xxx", "xxx", "xxx", "xxx", "legacy"]
        assert list(result.loc[3]) == ["xxx", "xxx", "xxx", "xxx", None]
        assert list(result.loc[4]) == ["xxx", "xxx", "xxx", "xxx", "no action"]
        assert list(result.loc[5]) == ["xxx", "xxx", "xxx",
                                       "xxx", "special chars: ♥"]
        assert list(result.loc[6]) == ["xxx", "xxx", "xxx",
                                       "xxx", "large text " * 2]

        # TODO: log when incorrect data type present?

        """mock data in list format in case needed for future tests"""
        # TODO: delete when done
        # assert list(result.loc[2]) == ["", "", "", None, "legacy"]
        # assert list(result.loc[3]) == [None, None, None, pd.NaT, None]
        # assert list(result.loc[4]) == ["Charlie", "charlie@ex.co.uk", 0,
        # "01/05/1975", "no action"]
        # assert list(result.loc[5]) == ["Δelta", 42, False, "1970-12-31",
        # "special chars: ♥"]
        # assert list(result.loc[6]) == [123, np.nan, np.nan, "2000-07-07",
        # "large text " * 2]

class TestCovertObfuscatedDFToCSVFile: 
    def test_returns_object_from_csv(self, mock_obfuscated_df, mock_csv_file_details): 
        result = convert_obf_df_to_file(mock_obfuscated_df, mock_csv_file_details)
        assert isinstance(result, object)  #TODO: check object is correct test? 

    def test_success_msg_logged_when_csv_file_object_returned(self, mock_obfuscated_df, mock_csv_file_details, caplog): 
        caplog.set_level(logging.INFO)
        convert_obf_df_to_file(mock_obfuscated_df, mock_csv_file_details)
        assert "obfuscated file ready" in caplog.text
    
    @pytest.mark.skip
    def test_error_if_not_converted_successfully(self):
        pass 


class TestCovertObfuscatedDFToJSONFile: 
    def test_returns_object_from_json(self, mock_obfuscated_df, mock_json_file_details): 
        result = convert_obf_df_to_file(mock_obfuscated_df, mock_json_file_details)
        assert isinstance(result, object)  #TODO: check object is correct test? 
    
    def test_success_msg_logged_when_csv_file_object_returned(self, mock_obfuscated_df, mock_json_file_details, caplog): 
        caplog.set_level(logging.INFO)
        convert_obf_df_to_file(mock_obfuscated_df, mock_json_file_details)
        assert "obfuscated file ready" in caplog.text
    
    @pytest.mark.skip
    def test_error_if_not_converted_successfully(self):
        pass 


class TestObfuscator:   
    @pytest.mark.skip
    def test_integration_csv(self): 
        pass 

@pytest.mark.skip
class General:
    def test_compatible_with_s3_put_object(self):
        pass  # necessary?

    def test_module_size_does_not_exceed_limit(self):
        pass  # necessary?

    def test_runtime_under_1m_with_file_up_to_1mb(self):
        pass  # necessary?

