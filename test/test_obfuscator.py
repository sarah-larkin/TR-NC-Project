from obfuscator.obfuscator import get_csv, obfuscate_data, obfuscator, validate_input_json
import pytest
import pandas as pd
from botocore.exceptions import ClientError, ParamValidationError
from copy import deepcopy
import numpy as np
import logging

"""
fixtures can be found in test/conftest.py file mocking:
s3_client,
mock_bucket,
mock_csv_file,
mock_df,
mock_json_for_csv_file
"""

class TestValidateJSON: 
    def test_validate_json_returns_parsed_dict_if_valid(self, mock_json_for_csv_file):
        result = validate_input_json(mock_json_for_csv_file)
        assert result == {
            "file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",
            "pii_fields": ["Name", "Email", "Phone", "DOB"]
        }

    # def test_validate_json_returns_False_if_invalid(self):
    #     result = validate_input_json('null')
    #     assert result == False
        # TODO: is bool output necessary?? 

    def test_success_msg_logged_when_valid_json_passed(self, caplog, mock_json_for_csv_file):
        caplog.set_level(logging.INFO)
        validate_input_json(mock_json_for_csv_file)
        assert "Valid JSON and valid fields" in caplog.text
    
    def test_error_raised_when_json_contains_syntax_error(self):
        with pytest.raises(ValueError):
            validate_input_json(
                '{"file_to_obfuscate":'
                '"s3://test_bucket_TR_NC/test_file.csv",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"]'
            )
            # no closing bracket

    def test_warning_logged_when_json_invalid(self, caplog):
        caplog.set_level(logging.WARNING)
        with pytest.raises(ValueError):  # has to be with pytest.raises
            validate_input_json(
                '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"],}'
            )
            # additional comma
        assert "Invalid JSON" in caplog.text

    def test_error_raised_when_empty_str_passed(self):
        with pytest.raises(ValueError):
            validate_input_json('')

    def test_error_raised_when_values_missing_from_json(self):
        with pytest.raises(ValueError):
            validate_input_json(
                '{"file_to_obfuscate": ,'
                '"pii_fields": }'
            )

    def test_error_raised_when_keys_missing_from_json(self):
        with pytest.raises(ValueError):  
            validate_input_json(
                '{"s3://test_bucket_TR_NC/test_file.csv",'
                '["Name", "Email", "Phone", "DOB"]}'
            )

    def test_2_key_value_pairs_are_passed(self, mock_json_for_csv_file): 
        result = validate_input_json(mock_json_for_csv_file)
        assert len(result) == 2

    def test_json_str_contains_specific_keys(self, mock_json_for_csv_file):
        """checks specific key names"""
        result = validate_input_json(mock_json_for_csv_file)
        key_names = result.keys()
        assert list(key_names) == ["file_to_obfuscate", "pii_fields"]
    @pytest.mark.skip
    def test_error_raised_if_different_keys_do_not_match(self, caplog): 
        caplog.set_level(logging.WARNING)
        with pytest.raises(ValueError):
            validate_input_json(
                '{"file": "s3://test_bucket_TR_NC/test_file.csv",'
                '"fields": ["Name", "Email", "Phone", "DOB"]}'
            )
        assert "Fields that are not permitted: ['file','fields']" in caplog.text
    @pytest.mark.skip
    def test_error_raised_if_required_keys_do_not_present(self, caplog): 
        caplog.set_level(logging.WARNING)
        validate_input_json(
            '{"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        )
        assert "Missing Fields: ['file_to_obfuscate']" in caplog.text
    

class TestExtractS3Details:
    def test(self):
        pass


class TestExtractFieldsToAlter:
    def test(self): 
        pass

@pytest.mark.skip
class TestGetCSV:
    def test_returns_df(self, mock_bucket, mock_csv_file, s3_client):
        response = get_csv(mock_bucket, mock_csv_file, s3_client)
        assert isinstance(response, pd.DataFrame)

    def test_returns_content_from_the_named_csv_file(
        self, mock_bucket, mock_csv_file, s3_client
    ):
        df = get_csv(mock_bucket, mock_csv_file, s3_client)
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

    def test_get_csv_raises_exception_if_csv_is_empty(self, mock_bucket, s3_client):
        empty_file = "empty_file.csv"
        s3_client.put_object(Bucket=mock_bucket, Key=empty_file, Body=b"")
        with pytest.raises(pd.errors.EmptyDataError) as exc:
            get_csv(mock_bucket, empty_file, s3_client)
        assert exc.value.args[0] == "No columns to parse from file"
        # TODO: check this out further,
        # error message could change with new versions

    def test_raises_clienterror_if_file_does_not_exist(self, mock_bucket, s3_client):
        """testing get_csv returns a client error
        for missing/incorrect file name"""
        non_file = "nonexistent_file.csv"
        with pytest.raises(ClientError):
            get_csv(mock_bucket, non_file, s3_client)

    def test_clienterror_error_code_when_file_does_not_exist(
        self, mock_bucket, s3_client
    ):
        """testing specific exception code is NoSuchKey
        for missing/incorrect file name"""
        incorrect_key = "incorrect_filename.csv"
        with pytest.raises(ClientError) as exc:
            get_csv(mock_bucket, incorrect_key, s3_client)
        err = exc.value.response["Error"]
        assert err["Code"] == "NoSuchKey"

    # def test_file_type(self): #better name needed
    #     #not uploading JSON with .csv extension
    #     pass

    # def test_file_has_missing_data(self):
    #     #eg. ID = int, name = str
    #     #necessary here?
    #     pass

    # def test_columns_contain_correct_data_type(self):
    #     #is this necessary?
    #     pass

    """#TODO:check approriate error is raised/logged if error occurs
        #Exceptions:
        # S3.Client.exceptions.NoSuchKey
        # S3.Client.exceptions.InvalidObjectState"""

@pytest.mark.skip
class TestObfuscateData:
    """fields: ["Name", "Email", "Phone", "DOB", "Notes"]"""

    # TODO: delete when done

    def test_new_object_returned(self, mock_df):
        """testing purity - checking new obejct is return"""
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        assert result is not mock_df

    def test_original_data_is_not_mutated(self, mock_df):
        """testing puring - checking original data has not been mutated"""
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
        assert list(result.loc[1]) == ["Bob", "xxx", "5551113333", "1985-02-03", ""]
        assert list(result.loc[7]) == [
            "Eve",
            "xxx",
            "(555) 999-0000",
            "1999-09-09",
            "final row",
        ]

    def test_sensitive_data_is_replaced_by_xxx_in_multiple_columns(self, mock_df):
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        assert list(result.loc[0]) == ["Alice", "xxx", "xxx", "xxx", "ok"]
        assert list(result.loc[1]) == ["Bob", "xxx", "xxx", "xxx", ""]
        assert list(result.loc[7]) == ["Eve", "xxx", "xxx", "xxx", "final row"]

    def test_returns_error_msg_if_column_does_not_exist(self, mock_df):
        result = obfuscate_data(mock_df, ["Address"])
        assert result == "invalid heading"

    def test_will_still_obfuscate_data_when_datatype_is_not_str(self, mock_df):
        result = obfuscate_data(mock_df, ["Name", "Email", "Phone", "DOB"])
        assert list(result.loc[2]) == ["xxx", "xxx", "xxx", "xxx", "legacy"]
        assert list(result.loc[3]) == ["xxx", "xxx", "xxx", "xxx", None]
        assert list(result.loc[4]) == ["xxx", "xxx", "xxx", "xxx", "no action"]
        assert list(result.loc[5]) == ["xxx", "xxx", "xxx", "xxx", "special chars: ♥"]
        assert list(result.loc[6]) == ["xxx", "xxx", "xxx", "xxx", "large text " * 2]

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

@pytest.mark.skip
class TestObfuscator:
    # check bucket name is valid and exists
    # check file name is valid and exists

    def test_csv_file_returns_bytestream(self, mock_json_for_csv_file):
        assert type(obfuscator(mock_json_for_csv_file)) == bytes

   

    def test_returns_error_msg_if_invalid_URL(self):
        with pytest.raises(ParamValidationError):
            obfuscator(
                '{"file_to_obfuscate": '
                '"test_bucket_TR_NC/test_file.csv",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
            )
            # missing s3://

    def test_returns_error_msg_if_URL_null(self):
        with pytest.raises(TypeError):
            obfuscator(
                '{"file_to_obfuscate": null,'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
            )

    @pytest.mark.skip
    def test_returns_error_msg_if_URL_is_empty_string(self):
        with pytest.raises(ParamValidationError):
            obfuscator(
                '{"file_to_obfuscate": "",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
            )

    def test_raises_error_if_not_accepted_file_type(self, mock_json_for_csv_file):
        # (ie. not [csv, (json, parquet)])
        # accepted_types = ["csv"]
        # o = urlparse("test_bucket_TR_NC/test_file.pdf") #pdf type
        # key = o.path.lstrip('/') #file_path/file_name (with first / removed)
        # file_name = key.split('/')[-1]
        # file_type = file_name.split('.')[-1]
        # assert file_type not in accepted_types
        assert (
            obfuscator(
                '{"file_to_obfuscate":'
                '"s3://test_bucket_TR_NC/test_file.pdf",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
            )
            == "invalid document type"
        )
        assert (
            obfuscator(
                '{"file_to_obfuscate":'
                '"s3://test_bucket_TR_NC/test_file.txt",'
                '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
            )
            == "invalid document type"
        )
        # TODO: handle this better?

    def test_raises_error_if_PII_is_null(self):
        with pytest.raises(TypeError):
            obfuscator(
                '{"file_to_obfuscate":'
                '"s3://test_bucket_TR_NC/test_file.csv",'
                '"pii_fields": null}'
            )

    @pytest.mark.skip
    def test_raises_error_if_no_PII_headings_specified(self):
        with pytest.raises(ValueError):
            obfuscator(
                '{"file_to_obfuscate":'
                '"s3://test_bucket_TR_NC/test_file.csv",'
                '"pii_fields": []}'
            )

@pytest.mark.skip
class General:
    def test_compatible_with_s3_put_object(self):
        pass  # necessary?

    def test_module_size_does_not_exceed_limit(self):
        pass  # necessary?

    def test_runtime_under_1m_with_file_up_to_1mb(self):
        pass  # necessary?

# TODO: add tests for logging and error correctness
# TODO: tests for edge cases such as invalid bucket, empty PII_fields, invalid headings 