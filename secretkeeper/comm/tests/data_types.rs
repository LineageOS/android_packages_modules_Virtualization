/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Unit tests for testing serialization & deserialization of exported data_types.

use ciborium::Value;
use secretkeeper_comm::data_types::error::{Error, SecretkeeperError, ERROR_OK};
use secretkeeper_comm::data_types::packet::{RequestPacket, ResponsePacket, ResponseType};
use secretkeeper_comm::data_types::request::Request;
use secretkeeper_comm::data_types::request_response_impl::Opcode;
use secretkeeper_comm::data_types::request_response_impl::{GetVersionRequest, GetVersionResponse};
use secretkeeper_comm::data_types::response::Response;

#[cfg(test)]
rdroidtest::test_main!();

#[cfg(test)]
mod tests {
    use super::*;
    use rdroidtest::test;

    test!(request_serialization_deserialization);
    fn request_serialization_deserialization() {
        let req = GetVersionRequest {};
        let packet = req.serialize_to_packet();
        assert_eq!(packet.opcode().unwrap(), Opcode::GetVersion);
        assert_eq!(
            RequestPacket::from_bytes(&packet.clone().into_bytes().unwrap()).unwrap(),
            packet
        );
        let req_deserialized = *GetVersionRequest::deserialize_from_packet(packet).unwrap();
        assert_eq!(req, req_deserialized);
    }

    test!(success_response_serialization_deserialization);
    fn success_response_serialization_deserialization() {
        let response = GetVersionResponse::new(1);
        let packet = response.serialize_to_packet();
        assert_eq!(packet.response_type().unwrap(), ResponseType::Success);
        assert_eq!(
            ResponsePacket::from_bytes(&packet.clone().into_bytes().unwrap()).unwrap(),
            packet
        );
        let response_deserialized = *GetVersionResponse::deserialize_from_packet(packet).unwrap();
        assert_eq!(response, response_deserialized);
    }

    test!(error_response_serialization_deserialization);
    fn error_response_serialization_deserialization() {
        let response = SecretkeeperError::RequestMalformed;
        let packet = response.serialize_to_packet();
        assert_eq!(packet.response_type().unwrap(), ResponseType::Error);
        assert_eq!(
            ResponsePacket::from_bytes(&packet.clone().into_bytes().unwrap()).unwrap(),
            packet
        );
        let response_deserialized = *SecretkeeperError::deserialize_from_packet(packet).unwrap();
        assert_eq!(response, response_deserialized);
    }

    test!(request_creation);
    fn request_creation() {
        let req: GetVersionRequest = *Request::new(vec![]).unwrap();
        assert_eq!(req, GetVersionRequest {});
    }

    test!(response_creation);
    fn response_creation() {
        let res: GetVersionResponse =
            *Response::new(vec![Value::from(ERROR_OK), Value::from(5)]).unwrap();
        assert_eq!(res.version(), 5);
    }

    test!(invalid_get_version_request_creation);
    fn invalid_get_version_request_creation() {
        // A request with non-zero arg is considered invalid.
        assert_eq!(
            <GetVersionRequest as Request>::new(vec![Value::Null]).unwrap_err(),
            Error::RequestMalformed
        );
    }

    test!(invalid_get_version_response_creation);
    fn invalid_get_version_response_creation() {
        // A response with non-zero error_code is an invalid success response.
        assert_eq!(
            <GetVersionResponse as Response>::new(vec![
                Value::from(SecretkeeperError::RequestMalformed as u16),
                Value::from(5)
            ])
            .unwrap_err(),
            Error::ResponseMalformed
        );

        // A response with incorrect size of array is invalid.
        assert_eq!(
            <GetVersionResponse as Response>::new(vec![
                Value::from(ERROR_OK),
                Value::from(5),
                Value::from(7)
            ])
            .unwrap_err(),
            Error::ResponseMalformed
        );

        // A response with incorrect type is invalid.
        <GetVersionResponse as Response>::new(vec![Value::from(ERROR_OK), Value::from("a tstr")])
            .unwrap_err();
    }

    test!(invalid_error_response_creation);
    fn invalid_error_response_creation() {
        // A response with ERROR_OK(0) as the error_code is an invalid error response.
        assert_eq!(
            <SecretkeeperError as Response>::new(vec![Value::from(ERROR_OK)]).unwrap_err(),
            Error::ResponseMalformed
        );
    }
}
