from obfuscator.obfuscator import (
    validate_input_json,
    extract_file_location_details,
    extract_fields_to_alter,
    get_file,
    convert_file_to_df,
    obfuscate_data,
    convert_obf_df_to_bytes,
    obfuscator,
)
import pytest
import pandas as pd
from botocore.exceptions import ClientError
from copy import deepcopy
import numpy as np
import logging
from moto import mock_aws
import json


class TestValidateJSON:
    def test_validate_json_returns_dict_if_json_valid(
        self, mock_input_json_for_csv_file, caplog
    ):
        caplog.set_level(logging.INFO)
        result = validate_input_json(mock_input_json_for_csv_file)
        assert result == {
            "file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",
            "pii_fields": ["Name", "Email", "Phone", "DOB"],
        }
        assert "Valid JSON and valid fields" in caplog.text

    def test_TypeError_raised_if_invalid_json_string(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = ({
            "file_to_obfuscate":
            "s3://tr-nc-test-source-files/Titanic-Dataset.csv",
            "pii_fields": ["Name", "Sex", "Age"],
        })  # dict not json
        with pytest.raises(TypeError):
            validate_input_json(input_json)
        assert (
            "invalid JSON: the JSON object must be str, " ""
            "bytes or bytearray, not dict"
        ) in caplog.text

    def test_JSONDecodeError_raised_when_json_invalid(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"],}'
        )  # additional comma
        with pytest.raises(json.JSONDecodeError):
            validate_input_json(input_json)
            assert (
                "invalid JSON syntax: Expecting ',' delimiter"
                in caplog.text
            )

    def test_ValueError_raised_format_not_dict(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = '["file_to_obfuscate","pii_fields"]'
        with pytest.raises(ValueError):
            validate_input_json(input_json)
            assert "dictionary format required" in caplog.text

    def test_confirm_json_str_contains_specific_keys(
        self, mock_input_json_for_csv_file
    ):
        result = validate_input_json(mock_input_json_for_csv_file)
        key_names = result.keys()
        assert list(key_names) == ["file_to_obfuscate", "pii_fields"]

    def test_ValueError_raised_if_missing_required_key(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = '{"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        with pytest.raises(ValueError):
            validate_input_json(input_json)
        assert (
            "missing key(s) from json str: ['file_to_obfuscate']"
        ) in caplog.text

    def test_ValueError_raised_if_missing_both_required_keys(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = '{"other": "other","thing": ["Name", "Email"]}'
        with pytest.raises(ValueError):
            validate_input_json(input_json)
        assert (
            "missing key(s) from json str: " ""
            "['file_to_obfuscate', 'pii_fields']"
        ) in caplog.text

    def test_ValueError_raised_if_file_value_type_invalid(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = (
            '{"file_to_obfuscate": [1,2,3],'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        )
        with pytest.raises(ValueError):
            validate_input_json(input_json)
        assert "file_to_obfuscate must have a string value" in caplog.text

    def test_valueError_raised_if_fieds_value_type_invalid(self, caplog):
        caplog.set_level(logging.ERROR)
        input_json = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": "Name"}'
        )
        with pytest.raises(ValueError):
            validate_input_json(input_json)
        assert "pii_fields must contain a list" in caplog.text


class TestExtractS3Details:
    def test_s3_details_returns_dict(self, mock_verified_input_for_csv):
        result = extract_file_location_details(mock_verified_input_for_csv)
        assert isinstance(result, dict)
        assert result == {
            "Scheme": "s3",
            "Bucket": "test_bucket_TR_NC",
            "Key": "test_file.csv",
            "File_Name": "test_file.csv",
            "File_Type": "csv",
        }

    def test_confirm_func_accepts_longer_file_path(self):
        file_path = (
            "s3://test_bucket_TR_NC/" "outer_folder/inner_folder/test_file.csv"
        )
        result = extract_file_location_details(
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

    def test_raises_and_logs_error_if_URL_is_empty_string(self, caplog):
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):
            extract_file_location_details(
                {
                    "file_to_obfuscate": "",
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )
        assert "no URL" in caplog.text

    def test_raises_and_logs_error_if_not_valid_s3_url(self, caplog):
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):
            extract_file_location_details(
                {
                    "file_to_obfuscate":
                    "HTTPS://test_bucket_TR_NC/test_file.csv",
                    "pii_fields": ["Name", "Email", "Phone", "DOB"],
                }
            )
            # missing s3://
            assert "not a valid s3 URL" in caplog.text

    def test_url_raises_and_logs_error_invalid_file_type(self, caplog):
        caplog.set_level(logging.ERROR)
        with pytest.raises(ValueError):
            extract_file_location_details(
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
            extract_file_location_details(
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
            mock_verified_input_for_csv
    ):
        caplog.set_level(logging.INFO)
        extract_fields_to_alter(mock_verified_input_for_csv)
        assert "pii fields extracted" in caplog.text

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

    def test_raises_and_logs_error_if_fields_not_strings(self, caplog):
        caplog.set_level(logging.ERROR)
        file_path = "s3://test_bucket_TR_NC/test_file.csv"
        with pytest.raises(TypeError):
            extract_fields_to_alter(
                {
                    "file_to_obfuscate": file_path,
                    "pii_fields": [1, 2, 3, "pii_fields"],
                }
            )
        expected_msg = "The headings : [1, 2, 3] are not strings"
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

    def test_get_file_returns_content_of_csv_file(
        self, mock_csv_file_details, mock_s3_client
    ):
        output = get_file(mock_csv_file_details, mock_s3_client)
        expected = (
            b"Name,Email,Phone,DOB,Notes\n"
            b"Alice,alice@example.com,+1-555-111-2222,1990-01-01,ok\n"
            b"Bob,bob_at_example.com,5551113333,1985-02-03\n"
            b"Charlie,charlie@ex.co.uk,0,01/05/1975,no action"
        )
        assert output == expected

    def test_get_file_raises_and_logs_ClientError_if_bucket_does_not_exist(
        self, mock_s3_client, caplog
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
        expected_msg = (
            "for s3://test_bucket_does_not_exist/test_file.csv -> "
            "NoSuchBucket : The specified bucket does not exist"
        )
        assert expected_msg in caplog.text

    def test_get_file_raises_ClientError_with_log_when_file_does_not_exist(
        self, mock_s3_client, mock_csv_file_details, caplog
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
        expected_msg = (
            "for s3://test_bucket_TR_NC/WRONG_file.csv -> "
            "NoSuchKey : The specified key does not exist."
        )
        assert expected_msg in caplog.text


class TestConvertFileToDFFromCSV:
    def test_convert_to_df_returns_df(
        self,
        mock_csv_file_details,
        mock_csv_as_bytes
    ):
        result = convert_file_to_df(mock_csv_file_details, mock_csv_as_bytes)
        assert isinstance(result, pd.DataFrame)

    def test_returns_content_from_the_named_csv_file(
        self, mock_csv_file_details, mock_csv_as_bytes
    ):
        df = convert_file_to_df(mock_csv_file_details, mock_csv_as_bytes)

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
        self, mock_bucket, mock_s3_client, caplog
    ):
        caplog.set_level(logging.ERROR)

        # put empty file in bucket:
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


class TestConvertFileToDFFromJSON:
    def test_convert_to_df_returns_df(
        self,
        mock_json_file_details,
        mock_json_as_bytes
    ):
        result = convert_file_to_df(mock_json_file_details, mock_json_as_bytes)
        assert isinstance(result, pd.DataFrame)

    def test_returns_content_from_the_named_json_file(
        self,
        mock_json_file_details,
        mock_s3_client
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
            None,
        ]
        assert list(df.loc[2]) == [
            "Charlie",
            "charlie@ex.co.uk",
            "0",
            "01/05/1975",
            "no action",
        ]
    
    def test_raises_and_logs_error_if_json_file_is_empty(
            self,
            mock_bucket,
            mock_s3_client,
            caplog
        ):
            caplog.set_level(logging.ERROR)

            # put empty file in bucket:
            mock_s3_client.put_object(
                Bucket=mock_bucket,
                Key="empty_file.json",
                Body=b''
            )

            mock_file_details = {
                "Scheme": "s3",
                "Bucket": mock_bucket,
                "Key": "empty_file.json",
                "File_Name": "empty_file.json",
                "File_Type": "json",
            }

            file_object = get_file(mock_file_details, mock_s3_client)

            with pytest.raises(ValueError):
                convert_file_to_df(mock_file_details, file_object)
            assert (
                "the file: empty_file.json from: test_bucket_TR_NC is empty"
                in caplog.text
            )
    
    def test_raises_and_logs_error_if_json_object_is_empty(
            self,
            mock_bucket,
            mock_s3_client,
            caplog
        ):
            caplog.set_level(logging.ERROR)

            # put empty file in bucket:
            mock_s3_client.put_object(
                Bucket=mock_bucket,
                Key="empty_file.json",
                Body=b'{}'
            )

            mock_file_details = {
                "Scheme": "s3",
                "Bucket": mock_bucket,
                "Key": "empty_file.json",
                "File_Name": "empty_file.json",
                "File_Type": "json",
            }

            file_object = get_file(mock_file_details, mock_s3_client)

            with pytest.raises(ValueError):
                convert_file_to_df(mock_file_details, file_object)
            assert (
                "the file: empty_file.json from: test_bucket_TR_NC is empty"
                in caplog.text
            )

class TestObfuscateData:
    def test_new_df_returned(self, mock_df):
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

    def test_logs_error_msg_if_column_does_not_exist(self, mock_df, caplog):
        caplog.set_level(logging.WARNING)
        obfuscate_data(mock_df, ["Address"])
        assert "The Heading : ['Address'] does not exist" in caplog.text

    def test_will_still_obfuscate_data_when_datatype_is_not_str(self, mock_df):
        result = obfuscate_data(mock_df, ["Name", "Email", "Phone", "DOB"])
        assert list(result.loc[2]) == [
            "xxx",
            "xxx",
            "xxx",
            "xxx",
            "legacy",
        ]  # DOB = None
        assert list(result.loc[3]) == [
            "xxx",
            "xxx",
            "xxx",
            "xxx",
            None
        ]  # all = None
        assert list(result.loc[4]) == [
            "xxx",
            "xxx",
            "xxx",
            "xxx",
            "no action",
        ]  # phone = 0
        assert list(result.loc[5]) == [
            "xxx",
            "xxx",
            "xxx",  # Phone = False, Email = 42
            "xxx",
            "special chars: ♥",
        ]
        assert list(result.loc[6]) == [
            "xxx",
            "xxx",
            "xxx",  # Name = 123, Email & Phne = np.nan
            "xxx",
            "large text " * 2,
        ]


class TestCovertObfuscatedDFToBytesForCSV:
    def test_returns_bytes_for_csv(
            self,
            mock_obfuscated_df,
            mock_csv_file_details
    ):
        result = convert_obf_df_to_bytes(
            mock_obfuscated_df,
            mock_csv_file_details
        )
        assert isinstance(result, bytes)

    def test_success_msg_logged_when_csv_bytestream_returned(
        self, mock_obfuscated_df, mock_csv_file_details, caplog
    ):
        caplog.set_level(logging.INFO)
        convert_obf_df_to_bytes(mock_obfuscated_df, mock_csv_file_details)
        assert "obfuscated file ready" in caplog.text


class TestCovertObfuscatedDFToJSONFile:
    def test_returns_bytes_for_json(
            self,
            mock_obfuscated_df,
            mock_json_file_details
    ):
        result = convert_obf_df_to_bytes(
            mock_obfuscated_df,
            mock_json_file_details
        )
        assert isinstance(result, bytes)

    def test_success_msg_logged_when_json_bytestream_returned(
        self, mock_obfuscated_df, mock_json_file_details, caplog
    ):
        caplog.set_level(logging.INFO)
        convert_obf_df_to_bytes(mock_obfuscated_df, mock_json_file_details)
        assert "obfuscated file ready" in caplog.text


class TestObfuscator:
    def test_integration_csv_happy_path(
        self, mock_s3_client, mock_csv_file_details, caplog
    ):

        valid_json = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        )

        caplog.set_level(logging.INFO)

        verified_input = validate_input_json(valid_json)
        file_details = extract_file_location_details(verified_input)
        fields_to_alter = extract_fields_to_alter(verified_input)
        data = get_file(file_details, mock_s3_client)
        df = convert_file_to_df(file_details, data)
        obf_df = obfuscate_data(df, fields_to_alter)
        convert_obf_df_to_bytes(obf_df, file_details)
        result = obfuscator(valid_json)

        assert isinstance(result, bytes)
        assert result == (
            b"Name,Email,Phone,DOB,Notes\n"
            b"xxx,xxx,xxx,xxx,ok\n"
            b"xxx,xxx,xxx,xxx,\n"
            b"xxx,xxx,xxx,xxx,no action\n"
        )
        assert "obfuscated file ready" in caplog.text

    def test_integration_csv_with_invalid_json_error(self, caplog):
        caplog.set_level(logging.ERROR)
        invalid_json = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"],'
        )  # no closing bracket
        with pytest.raises(json.JSONDecodeError):
            validate_input_json(invalid_json)
            assert "Invalid JSON" in caplog.text

    def test_integration_csv_with_invalid_s3_url(self, caplog):
        caplog.set_level(logging.ERROR)
        invalid_url = (
            '{"file_to_obfuscate": "test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        )
        with pytest.raises(ValueError):
            verified_input = validate_input_json(invalid_url)
            extract_file_location_details(verified_input)
            assert "not a valid s3 URL" in caplog.text

    def test_integration_csv_with_invalid_s3_field_type(self, caplog):
        caplog.set_level(logging.ERROR)
        invalid_pii_fields = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": [1, true, 3, false, "Four"]}'
        )
        with pytest.raises(TypeError):
            verified_input = validate_input_json(invalid_pii_fields)
            extract_fields_to_alter(verified_input)
        assert (
            "The headings : [1, True, 3, False] are not strings"
         ) in caplog.text

    def test_integration_csv_with_invalid_file_name(
        self, mock_s3_client, mock_bucket, caplog  # keep in
    ):

        invalid_file_input = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/random_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        )

        with pytest.raises(ClientError):
            verified_input = validate_input_json(invalid_file_input)
            file_details = extract_file_location_details(verified_input)
            get_file(file_details, mock_s3_client)
        expected_msg = (
            "for s3://test_bucket_TR_NC/random_file.csv -> "
            "NoSuchKey : The specified key does not exist."
        )
        assert expected_msg in caplog.text

    def test_integration_csv_with_empty_data(
            self,
            mock_bucket,
            mock_s3_client,
            caplog
    ):
        caplog.set_level(logging.ERROR)

        # put empty file in bucket:
        mock_s3_client.put_object(
            Bucket=mock_bucket,
            Key="no_data_file.csv",
            Body=b""
        )

        invalid_file_input = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/no_data_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "DOB"]}'
        )

        with pytest.raises(pd.errors.EmptyDataError):
            verified_input = validate_input_json(invalid_file_input)
            file_details = extract_file_location_details(verified_input)
            data = get_file(file_details, mock_s3_client)
            convert_file_to_df(file_details, data)
        assert (
            "the file: no_data_file.csv from: test_bucket_TR_NC is empty"
            in caplog.text
        )

    def test_integration_csv_with_invalid_heading(
        self,
        mock_bucket,
        mock_csv_file_details,
        mock_s3_client,
        caplog
    ):
        caplog.set_level(logging.ERROR)

        invalid_file_input = (
            '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv",'
            '"pii_fields": ["Name", "Email", "Phone", "Age"]}'
        )

        verified_input = validate_input_json(invalid_file_input)
        file_details = extract_file_location_details(verified_input)
        fields_to_alter = extract_fields_to_alter(verified_input)
        data = get_file(file_details, mock_s3_client)
        df = convert_file_to_df(file_details, data)
        obfuscate_data(df, fields_to_alter)
        assert "The Heading : ['Age'] does not exist" in caplog.text


@pytest.mark.skip
class General:
    def test_compatible_with_s3_put_object(self):
        pass  # necessary?
