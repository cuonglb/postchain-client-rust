//! Operation parameter handling and data type conversion utilities.
//! 
//! This module provides functionality for handling operation parameters,
//! data type conversions, and serialization/deserialization of various
//! data types used in blockchain operations.
//! 
//! # Features
//! - Generic parameter type system supporting various data types
//! - Conversion between Rust structs and operation parameters
//! - Serialization/deserialization support for complex data types
//! - Support for large integers and binary data
//! 
//! # Example
//! ```
//! use std::collections::BTreeMap;
//! use crate::utils::operation::{Operation, Params};
//! 
//! // Create operation parameters
//! let params = vec![
//!     ("key", Params::Text("value".to_string())),
//!     ("number", Params::Integer(42))
//! ];
//! 
//! // Create an operation
//! let operation = Operation::from_dict("my_operation", params);
//! ```

extern crate num_bigint;

use std::{collections::BTreeMap, fmt::Debug};
use num_bigint::BigInt;
use bigdecimal::BigDecimal;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

#[allow(unused_imports)]
use postchain_client_derive::StructMetadata;

pub trait StructMetadata {
    fn field_names_and_types() -> std::collections::BTreeMap<String, String>;
}

/// Represents different types of operation parameters.
/// 
/// This enum provides a type-safe way to handle various data types
/// used in blockchain operations, including primitive types, collections,
/// and special types like BigInteger.
#[derive(Clone, Debug, PartialEq)]
pub enum Params {
    /// Represents a null value
    Null,
    /// Represents a boolean value (true/false)
    Boolean(bool),
    /// Represents a 64-bit signed integer
    Integer(i64),
    /// Represents an arbitrary-precision integer using BigInt
    BigInteger(BigInt),
    /// Represents an arbitrary-precision decimal using BigDecimal
    Decimal(BigDecimal),
    /// Represents a UTF-8 encoded string
    Text(String),
    /// Represents a raw byte array
    ByteArray(Vec<u8>),
    /// Represents an ordered collection of Params
    Array(Vec<Params>),
    /// Represents a key-value mapping where keys are strings
    Dict(BTreeMap<String, Params>)
}

pub type QueryParams = Params;
pub type OperationParams = Params;

/// Deserializes a string into a BigInt.
/// 
/// This function is used with serde to deserialize string-encoded
/// big integers into BigInt type.
/// 
/// # Arguments
/// * `deserializer` - The deserializer to use
/// 
/// # Returns
/// Result containing either the deserialized BigInt or an error
#[allow(dead_code)]
fn deserialize_bigint<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let de_str: String = serde::Deserialize::deserialize(deserializer)?;
    
    BigInt::parse_bytes(de_str.as_bytes(), 10)
        .ok_or(serde::de::Error::custom("Failed to parse BigInt"))
}

/// Deserializes a base64 string into a byte array.
/// 
/// This function is used with serde to deserialize base64-encoded
/// strings into byte arrays.
/// 
/// # Arguments
/// * `deserializer` - The deserializer to use
/// 
/// # Returns
/// Result containing either the deserialized byte array or an error
#[allow(dead_code)]
fn deserialize_byte_array<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let base64_str: String = serde::Deserialize::deserialize(deserializer)?;
    general_purpose::STANDARD.decode(&base64_str).map_err(serde::de::Error::custom)
}


/// Serializes a BigInt into a string.
/// 
/// This function is used with serde to serialize BigInt values
/// into string format.
/// 
/// # Arguments
/// * `bigint` - The BigInt to serialize
/// * `serializer` - The serializer to use
/// 
/// # Returns
/// Result containing either the serialized string or an error
#[allow(dead_code)]
fn serialize_bigint<S>(bigint: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bigint_str = bigint.to_string();
    serializer.serialize_str(&bigint_str)
}

/// Custom serialization for `BigDecimal`.
///
/// This function converts a `BigDecimal` value into a string representation,
/// which is then serialized using the provided serializer.
///
/// # Arguments
/// * `bigdecimal` - A reference to the `BigDecimal` value to serialize.
/// * `serializer` - The serializer to use for converting the `BigDecimal` into a string.
///
/// # Returns
/// Returns the serialized string representation of the `BigDecimal` if successful,
/// or an error if serialization fails.
///
/// # Example
/// ```
/// #[derive(Debug, serde::Serialize)]
/// struct MyStruct {
///     #[serde(serialize_with = "serialize_bigdecimal")]
///     value: BigDecimal,
/// }
///
/// let my_struct = MyStruct { value: BigDecimal::from_str("3.14").unwrap() };
/// let json = serde_json::to_string(&my_struct).unwrap();
///
#[allow(dead_code)]
fn serialize_bigdecimal<S>(bigdecimal: &BigDecimal, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&bigdecimal.to_string())
}

/// Custom deserialization for `BigDecimal`.
///
/// This function takes a string representation of a `BigDecimal` and converts it
/// back into a `BigDecimal` value.
///
/// # Arguments
/// * `deserializer` - The deserializer to use for converting the string into a `BigDecimal`.
///
/// # Returns
/// Returns the deserialized `BigDecimal` if successful, or an error if deserialization fails.
///
/// # Example
/// ```
/// #[derive(Debug, serde::Deserialize)]
/// struct MyStruct {
///     #[serde(deserialize_with = "deserialize_bigdecimal")]
///     value: BigDecimal,
/// }
///
/// let json = r#"{"value": "3.14"}"#;
/// let my_struct: MyStruct = serde_json::from_str(json).unwrap();
/// ```
#[allow(dead_code)]
fn deserialize_bigdecimal<'de, D>(deserializer: D) -> Result<BigDecimal, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    BigDecimal::from_str(&s)
        .map_err(serde::de::Error::custom)
}

/// Represents a blockchain operation with parameters.
/// 
/// An operation can contain either a dictionary of named parameters
/// or a list of unnamed parameters, along with an operation name.
#[derive(Clone, Debug, PartialEq)]
#[derive(Default)]
pub struct Operation<'a> {
    /// Dictionary of named parameters
    /// List of unnamed parameters
    /// Name of the operation
    pub dict: Option<Vec<(&'a str, Params)>>,
    pub list: Option<Vec<Params>>,
    pub operation_name: Option<&'a str>,
}


/// Checks if a vector of JSON values represents a byte array.
/// 
/// # Arguments
/// * `value` - Vector of JSON values to check
/// 
/// # Returns
/// true if all values are valid u8 numbers
fn is_vec_u8(value: &[serde_json::Value]) -> bool {
    value.iter().all(|v| {
            if let serde_json::Value::Number(n) = v {
                n.is_u64() && n.as_u64().unwrap() <= u8::MAX as u64
            } else {
                false
            }
        })    
}

impl<'a> Operation<'a> {
    /// Creates a new Operation from a dictionary of parameters.
    /// 
    /// # Arguments
    /// * `operation_name` - Name of the operation
    /// * `params` - Vector of key-value parameter pairs
    /// 
    /// # Returns
    /// A new Operation instance with dictionary parameters
    pub fn from_dict(operation_name: &'a str, params: Vec<(&'a str, Params)>) -> Self {
        Self {
            dict: Some(params),
            operation_name: Some(operation_name),
            ..Default::default()
        }
    }

    /// Creates a new Operation from a list of parameters.
    /// 
    /// # Arguments
    /// * `operation_name` - Name of the operation
    /// * `params` - Vector of parameters
    /// 
    /// # Returns
    /// A new Operation instance with list parameters
    pub fn from_list(operation_name: &'a str, params: Vec<Params>) -> Self {
        Self {
            list: Some(params),
            operation_name: Some(operation_name),
            ..Default::default()
        }
    }
}

impl Params {
    /// Converts a boxed f64 value to its string representation.
    /// 
    /// # Arguments
    /// * `val` - Boxed f64 value to convert
    /// 
    /// # Returns
    /// String representation of the decimal value
    pub fn decimal_to_string(val: Box<f64>) -> String {
        val.to_string()
    }

    /// Converts a dictionary parameter into an array of alternating keys and values.
    ///
    /// # Returns
    ///
    /// A vector where each key from the dictionary is followed by its corresponding value as `Params`.
    ///
    /// # Panics
    ///
    /// Panics if called on a `Params` variant that is not `Dict`.
    ///
    /// # Example
    /// ```
    /// let dict = Params::Dict(BTreeMap::from([
    ///     ("a".to_string(), Params::Integer(1)),
    ///     ("b".to_string(), Params::Text("foo".to_string())),
    /// ]));
    /// let arr = dict.dict_to_array();
    /// // arr = [Params::Text("a"), Params::Integer(1), Params::Text("b"), Params::Text("foo")]
    /// ```
    pub fn dict_to_array(self) -> Vec<Params> {
        match self {
            Params::Dict(dict) => {
                let mut array_data = Vec::new();
                for (key, value) in dict.into_iter() {
                    array_data.push(Params::Text(key));
                    array_data.push(value);
                }
                array_data
            },
            _ => panic!("Expected Params::Dict, found {self:?}"),
        }
    }

    /// Converts a dictionary parameter to an array of its values.
    ///
    /// # Returns
    ///
    /// A vector containing only the values from the dictionary, in the order of their keys.
    ///
    /// # Panics
    ///
    /// Panics if called on a `Params` variant that is not `Dict`.
    ///
    /// # Example
    /// ```
    /// let dict = Params::Dict(BTreeMap::from([
    ///     ("a".to_string(), Params::Integer(1)),
    ///     ("b".to_string(), Params::Text("foo".to_string())),
    /// ]));
    /// let arr = dict.dict_to_array_values();
    /// // arr = [Params::Integer(1), Params::Text("foo")]
    /// ```
    pub fn dict_to_array_values(self) -> Vec<Params> {
        match self {
            Params::Dict(dict) => {
                let values: Vec<Params> = dict.into_values().collect();
                values
            },
            _ => panic!("Expected Params::Dict, found {self:?}"),
        }
    }

    /// Checks if the parameter value is empty.
    /// 
    /// Works with Array, Dict, ByteArray, and Text parameter types.
    /// 
    /// # Returns
    /// true if the parameter value is empty
    /// 
    /// # Panics
    /// Panics if called on parameter types that don't support emptiness check
    pub fn is_empty(self) -> bool {
        match self {
            Params::Array(array) => array.is_empty(),
            Params::Dict(dict) => dict.is_empty(),
            Params::ByteArray(bytearray) => bytearray.is_empty(),
            Params::Text(text) => text.is_empty(),
            _ => panic!("Cannot check empty of this type {self:?}")
        }
    }

    /// Returns the length of the parameter value.
    /// 
    /// Works with Array, Dict, ByteArray, and Text parameter types.
    /// 
    /// # Returns
    /// Length of the parameter value
    /// 
    /// # Panics
    /// Panics if called on parameter types that don't support length
    pub fn len(self) -> usize {
        match self {
            Params::Array(array) => array.len(),
            Params::Dict(dict) => dict.len(),
            Params::ByteArray(bytearray) => bytearray.len(),
            Params::Text(text) => text.len(),
            _ => panic!("Cannot get length of this type {self:?}")
        }
    }

    pub fn to_hex_encode(self) -> String {
        match self {
            Params::ByteArray(bytearray) => hex::encode(bytearray),
            _ => panic!("Expected Params::ByteArray, found {self:?}"),
        }
    }

    /// Converts a dictionary parameter to a Rust struct.
    /// 
    /// # Type Parameters
    /// * `T` - The target struct type that implements Default + Debug + Deserialize
    /// 
    /// # Returns
    /// Result containing either the converted struct or an error message
    /// 
    /// # Example
    /// ```
    /// #[derive(Debug, Default, serde::Deserialize)]
    /// struct MyStruct {
    ///     field: String,
    ///     value: i64,
    /// }
    /// 
    /// let dict = Params::Dict(/* ... */);
    /// let result: Result<MyStruct, String> = dict.to_struct();
    /// ```
    pub fn to_struct<T>(&self) -> Result<T, String>
    where
        T: Default + std::fmt::Debug + for<'de> serde::Deserialize<'de>,
    {
        match self {
            Params::Dict(_) => {
                let json_value = self.to_json_value();
                
                serde_json::from_value(json_value)
                    .map_err(|e| format!("Failed to convert Params to struct: {e}"))
            },
            _ => Err(format!("Expected Params::Dict, found {self:?}")),
        }
    }

    /// Converts the parameter to a serde_json::Value.
    /// 
    /// This method handles all parameter types, including complex types
    /// like BigInteger and ByteArray.
    /// 
    /// # Returns
    /// JSON representation of the parameter
    pub fn to_json_value(&self) -> serde_json::Value {
        match *self {
            Params::Null => serde_json::Value::Null,
            Params::Boolean(b) => serde_json::Value::Bool(b),
            Params::Integer(i) => serde_json::Value::Number(serde_json::Number::from(i)),
            Params::BigInteger(ref big_int) => serde_json::Value::String(big_int.to_string()),
            Params::Decimal(ref big_decimal) => serde_json::Value::String(big_decimal.to_string()),
            Params::Text(ref text) => serde_json::Value::String(text.to_string()),
            Params::ByteArray(ref bytearray) => {
                if bytearray.len() == 33 {
                    serde_json::Value::String(hex::encode(bytearray))
                } else {
                    let base64_encoded = general_purpose::STANDARD.encode(bytearray);
                    serde_json::Value::String(base64_encoded)
                }
            },
            Params::Array(ref array) => {
                let json_array: Vec<serde_json::Value> = array.iter().map(|param| param.to_json_value()).collect();
                serde_json::Value::Array(json_array)
            },
            Params::Dict(ref dict) => {
                let json_object: serde_json::Map<String, serde_json::Value> = dict.iter()
                    .map(|(key, value)| (key.to_string(), value.to_json_value()))
                    .collect();
                serde_json::Value::Object(json_object)
            },
        }
    }

    /// Creates a parameter from a Rust struct.
    /// 
    /// # Type Parameters
    /// * `T` - The source struct type that implements Debug + Serialize
    /// 
    /// # Arguments
    /// * `struct_instance` - Reference to the struct to convert
    /// 
    /// # Returns
    /// Dictionary parameter containing the struct's fields
    /// 
    /// # Example
    /// ```
    /// #[derive(Debug, serde::Serialize)]
    /// struct MyStruct {
    ///     field: String,
    ///     value: i64,
    /// }
    /// 
    /// let my_struct = MyStruct { field: "test".into(), value: 42 };
    /// let params = Params::from_struct(&my_struct);
    /// ```
    pub fn from_struct<T>(struct_instance: &T) -> Params
    where
        T: std::fmt::Debug + serde::Serialize + StructMetadata,
    {
        let json_value = serde_json::to_value(struct_instance)
            .expect("Failed to convert struct to JSON value");

        let fnat = T::field_names_and_types();

        Params::Dict(Self::json_value_to_params_dict(json_value, fnat))
    }

    /// Converts a JSON value to a parameter dictionary, utilizing a provided function name to argument type (fnat) mapping.
    ///
    /// # Parameters
    /// * `value`: The JSON value to be converted.
    /// * `fnat`: A mapping of function names to argument types, used to determine the type of each parameter.
    ///
    /// # Returns
    /// A `BTreeMap` containing the converted parameters, where each key is a parameter name and each value is a `Params` object.
    ///
    /// # Notes
    /// * This function assumes that the input JSON value is an object, and will only process key-value pairs within that object.
    /// * The `fnat` mapping is used to determine the type of each parameter, and should contain a mapping of function names to argument types.
    /// * If a key in the input JSON value is not present in the `fnat` mapping, the function will use a default type for that parameter.
    fn json_value_to_params_dict(value: serde_json::Value, fnat: BTreeMap<String, String>) -> BTreeMap<String, Params> {
        let mut dict: BTreeMap<String, Params> = BTreeMap::new();

        if let serde_json::Value::Object(map) = value {
            for (key, val) in map {
                let f_type = fnat.get(&key).cloned();
                dict.insert(key, Self::value_to_params(val, f_type));
            }
        }

        dict
    }

    /// Creates a list of parameters from a Rust struct.
    /// 
    /// Similar to from_struct, but returns a vector of values
    /// instead of a dictionary.
    /// 
    /// # Type Parameters
    /// * `T` - The source struct type that implements Debug + Serialize
    /// 
    /// # Arguments
    /// * `struct_instance` - Reference to the struct to convert
    /// 
    /// # Returns
    /// Vector of parameters containing the struct's field values
    pub fn from_struct_to_list<T>(struct_instance: &T) -> Vec<Params>
    where
        T: std::fmt::Debug + serde::Serialize + StructMetadata,
    {
        let json_value = serde_json::to_value(struct_instance)
            .expect("Failed to convert struct to JSON value");

        let mut vec = Vec::new();

        let fnat = T::field_names_and_types();

        if let serde_json::Value::Object(map) = json_value {
            for (key, val) in map {
                let f_type = fnat.get(&key).cloned();
                vec.push(Self::value_to_params(val, f_type));
            }
        }

        vec
    }

    /// Converts a struct into a Vec<(String, Params)>.
    /// 
    /// # Type Parameters
    /// * `T` - The struct type that implements Debug + Serialize
    /// 
    /// # Arguments
    /// * `struct_instance` - Reference to the struct to convert
    /// 
    /// # Returns
    /// Vector of tuples containing string keys and Params values
    pub fn from_struct_to_vec<T>(struct_instance: &T) -> Vec<(String, Params)>
    where
        T: std::fmt::Debug + serde::Serialize,
    {
        let json_value = serde_json::to_value(struct_instance)
            .expect("Failed to convert struct to JSON value");

        let mut vec = Vec::new();

        if let serde_json::Value::Object(map) = json_value {
            for (key, val) in map {
                vec.push((key, Self::value_to_params(val, None)));
            }
        }

        vec
    }

    /// Converts a JSON value to a parameter.
    ///
    /// This function handles the conversion of various JSON types to their corresponding parameter types.
    ///
    /// ### Arguments
    ///
    /// * `value`: The JSON value to convert.
    /// * `field_type`: An optional string indicating the type of the field. This is used to determine the type of the converted parameter.
    ///
    /// ### Returns
    ///
    /// The converted parameter.
    ///
    /// ### Notes
    ///
    /// * If the `field_type` is `Some` and contains "BigInt", the function will attempt to parse the JSON string value as a BigInteger.
    /// * If the `field_type` is `Some` and contains "BigDecimal", the function will attempt to parse the JSON string value as a BigDecimal.
    /// * If the JSON value is an array and all elements are numbers, the function will attempt to convert it to a byte array.
    fn value_to_params(value: serde_json::Value, field_type: Option<String>) -> Params {
        match value {
            serde_json::Value::Null => Params::Null,
            serde_json::Value::Bool(b) => Params::Boolean(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Params::Integer(i)
                } else {
                    Params::Null
                }
            },
            serde_json::Value::String(s) => {
                match field_type {
                    Some(val) if val.contains("BigInt") => {
                        match BigInt::parse_bytes(s.as_bytes(), 10) {
                            Some(big_int) => Params::BigInteger(big_int),
                            None => panic!("Required field is not a valid BigInteger"),
                        }
                    },
                    Some(val) if val.contains("BigDecimal") => {
                        match BigDecimal::parse_bytes(s.as_bytes(), 10) {
                            Some(big_decimal) => Params::Decimal(big_decimal),
                            None => panic!("Required field is not a valid BigDecimal"),
                        }
                    },
                    _ => Params::Text(s)
                }
            },
            serde_json::Value::Array(arr) => {
                let is_vec_u8 = is_vec_u8(&arr);
                if is_vec_u8 {
                    let barr: Vec<u8> = arr.iter().map(|v|{v.as_u64().unwrap() as u8}).collect();
                    return Params::ByteArray(barr)
                }
                let params_array: Vec<Params> = arr.into_iter().map(|x|{
                    Self::value_to_params(x, None)
                }).collect();
                Params::Array(params_array)
            },
            serde_json::Value::Object(dict) => {
                let params_dict: BTreeMap<String, Params> = dict.into_iter().map(|(k, v)| ( k, Self::value_to_params(v, None))).collect();
                Params::Dict(params_dict)
            }
        }
    }

    /// Prints debug information about the parameter.
    /// 
    /// This method is only available in debug builds and provides
    /// detailed information about the parameter's content.
    /// 
    /// # Arguments
    /// * `self` - The parameter to debug print
    #[cfg(debug_assertions)]
    pub fn debug_print(&self) {
        match self {
            Params::Array(array) => {
                    for item in array {
                        item.debug_print();
                    }
            } 
            Params::Dict(dict) => {
                    for item in dict {
                        eprintln!("key = {}", item.0);
                        eprintln!("value = ");
                        item.1.debug_print();
                    }
            }
            Params::ByteArray(val) => {
                eprintln!("{:?}", hex::encode(val));
            }
            _ =>
                eprintln!("{self:?}")
        }
    }
}

/// Converts `Params` to `bool`.
///
/// # Panics
/// Panics if the `Params` variant is not `Params::Boolean`.
impl From<Params> for bool {
    fn from(value: Params) -> Self {
        match value {
            Params::Boolean(val) => val,
            _ => panic!("Cannot convert {value:?} to bool")
        }
    }
}

/// Converts `Params` to `i64`.
///
/// # Panics
/// Panics if the `Params` variant is not `Params::Integer`.
impl From<Params> for i64 {
    fn from(value: Params) -> Self {
        match value {
            Params::Integer(val) => val,
            _ => panic!("Cannot convert {value:?} to i64")
        }
    }
}

/// Converts `Params` to `BigInt`.
///
/// # Panics
/// Panics if the `Params` variant is not `Params::BigInteger`.
impl From<Params> for BigInt {
    fn from(value: Params) -> Self {
        match value {
            Params::BigInteger(val) => val,
            _ => panic!("Cannot convert {value:?} to BigInt")
        }
    }
}

/// Converts `Params` to `BigDecimal`.
///
/// # Panics
/// Panics if the `Params` variant is not `Params::Decimal`.
impl From<Params> for BigDecimal {
    fn from(value: Params) -> Self {
        match value {
            Params::Decimal(val) => val,
            _ => panic!("Cannot convert {value:?} to BigDecimal")
        }
    }
}

/// Converts `Params` to `String`.
///
/// # Panics
/// Panics if the `Params` variant is not `Params::Text`.
impl From<Params> for String {
    fn from(value: Params) -> Self {
        match value {
            Params::Text(val) => val,
            _ => panic!("Cannot convert {value:?} to String")
        }
    }
}

/// Converts `Params` to `Vec<u8>`.
///
/// # Panics
/// Panics if the `Params` variant is not `Params::ByteArray`.
impl From<Params> for Vec<u8> {
    fn from(value: Params) -> Self {
        match value {
            Params::ByteArray(val) => val,
            _ => panic!("Cannot convert {value:?} to Vec<u8>")
        }
    }
}

/// Implements conversion from Params to `Vec<Params>`.
/// 
/// This implementation allows converting an Array parameter
/// into a vector of parameters.
/// 
/// # Panics
/// Panics if the parameter is not an Array type
impl From<Params> for Vec<Params> {
    fn from(val: Params) -> Self {
        match val {
            Params::Array(array) => array,
            _ => panic!("Cannot convert {val:?} into Vec<Params>"),
        }
    }
}

/// Implements conversion from Params to BTreeMap<String, Params>.
/// 
/// This implementation allows converting a Dict parameter
/// into a BTreeMap of string keys and parameter values.
/// 
/// # Panics
/// Panics if the parameter is not a Dict type
impl From<Params> for BTreeMap<String, Params> {
    fn from(val: Params) -> Self {
        match val {
            Params::Dict(dict) => dict,
            _ => panic!("Cannot convert {val:?} into BTreeMap"),
        }
    }
}

#[test]
fn test_serialize_struct_to_param_dict() {
    #[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq)]
    struct TestStruct2 {
        foo: String
    }

    #[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, StructMetadata)]
    struct TestStruct1 {
        foo: String,
        bar: i64,
        #[serde(serialize_with = "serialize_bigint", deserialize_with = "deserialize_bigint")]
        bigint: num_bigint::BigInt,
        ok: bool,
        nested_struct: TestStruct2,
        #[serde(deserialize_with="deserialize_byte_array")]
        bytearray: Vec<u8>,
    }

    let ts1 = TestStruct1 {
        foo: "foo".to_string(), bar: 1, ok: true,
        bigint: num_bigint::BigInt::from(170141183460469231731687303715884105727_i128),
        nested_struct: TestStruct2{foo: "bar".to_string()}, bytearray: vec![1, 2, 3, 4, 5]
    };

    let r: Params = Params::from_struct(&ts1);

    let m: Result<TestStruct1, String> = r.to_struct();

    assert_eq!(ts1, m.unwrap());
    
}

#[test]
fn test_deserialize_param_dict_to_struct() {
    use std::str::FromStr;

    /// We have two options here for deserialization big integer:
    /// 1. Use `String` struct
    /// 2. Use `num_bigint::BigInt` struct with serder custom function
    ///    name `deserialize_bigint`
    #[derive(Debug, Default, serde::Deserialize, PartialEq)]
    struct TestNestedStruct {
        bigint_as_string: String,
        #[serde(deserialize_with = "deserialize_bigint")]
        bigint_as_num_bigint: num_bigint::BigInt
    }

    #[derive(Debug, Default, serde::Deserialize, PartialEq)]
    struct TestStruct {
        x: i64,
        y: i64,
        z: String,
        l: bool,
        n: BigDecimal,
        m: String,
        dict: TestNestedStruct,
        array: Vec<serde_json::Value>,
        t: Option<bool>
    }

    let bigint = num_bigint::BigInt::from(100000000000000000000000_i128);
    let bytearray_value = b"1234";
    let bytearray_base64_encoded = general_purpose::STANDARD.encode(bytearray_value);

    let ts = TestStruct{
        t: None,
        x: 1, y: 2, z: "foo".to_string(), dict: TestNestedStruct {
            bigint_as_string: bigint.to_string(),
            bigint_as_num_bigint: 100000000000000000000000_i128.into()
        }, l: true, n: BigDecimal::from_str("3.14").unwrap(), m: bytearray_base64_encoded, array: vec![
            serde_json::Value::Number(serde_json::Number::from(1_i64)),
            serde_json::Value::String("foo".to_string()),
            ]
    };

    let mut nested_params: BTreeMap<String, Params> = BTreeMap::new();
    nested_params.insert("bigint_as_string".to_string(), Params::BigInteger(bigint.clone()));
    nested_params.insert("bigint_as_num_bigint".to_string(), Params::BigInteger(bigint.clone()));

    let mut params: BTreeMap<String, Params> = BTreeMap::new();
    params.insert("t".to_string(), Params::Null);
    params.insert("x".to_string(), Params::Integer(1));
    params.insert("y".to_string(), Params::Integer(2));
    params.insert("z".to_string(), Params::Text("foo".to_string()));
    params.insert("dict".to_string(), Params::Dict(nested_params));
    params.insert("l".to_string(), Params::Boolean(true));
    params.insert("n".to_string(), Params::Decimal(BigDecimal::from_str("3.14").unwrap()));
    params.insert("m".to_string(), Params::ByteArray(bytearray_value.to_vec()));
    params.insert("array".to_string(), Params::Array(vec![Params::Integer(1), Params::Text("foo".to_string())]));

    let params_dict = Params::Dict(params);
    let result: Result<TestStruct, String> = params_dict.to_struct();

    if let Ok(val) = result {
        assert_eq!(ts, val);
    } else {
        panic!("Error deserializing params: {}", result.unwrap_err());
    }
}

#[test]
fn test_serialize_deserialize_bigint() {
    let large_int_str = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let large_int = BigInt::parse_bytes(large_int_str.as_bytes(), 10).unwrap();

    #[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, StructMetadata)]
    struct TestStruct {
        #[serde(serialize_with = "serialize_bigint", deserialize_with = "deserialize_bigint")]
        bigint1: num_bigint::BigInt,
    }

    let ts = TestStruct {
        bigint1: large_int.clone(),
    };

    let mut params: BTreeMap<String, Params> = BTreeMap::new();
    params.insert("bigint1".to_string(), Params::BigInteger(large_int));
    
    let result: Result<TestStruct, String> = Params::Dict(params).to_struct();

    if let Ok(val) = result {
        assert_eq!(ts, val);
    } else {
        panic!("Error deserializing params: {}", result.unwrap_err());
    }
}

#[test]
fn test_serialize_deserialize_bigdecimal() {
    use std::str::FromStr;

    let large_int_str = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let large_int = BigInt::parse_bytes(large_int_str.as_bytes(), 10).unwrap();

    #[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, StructMetadata)]
    struct TestStruct {
        no_number: String,
        #[serde(serialize_with = "serialize_bigint", deserialize_with = "deserialize_bigint")]
        bigint: BigInt,
        #[serde(serialize_with = "serialize_bigdecimal", deserialize_with = "deserialize_bigdecimal")]
        bigdecimal: BigDecimal
    }

    let ts = TestStruct {
        no_number: "Hello!".to_string(),
        bigdecimal: BigDecimal::from_str(".02").unwrap(),
        bigint: large_int
    };

    let r: Params = Params::from_struct(&ts);

    let m: Result<TestStruct, String> = r.to_struct();

    assert_eq!(ts, m.unwrap());
}

#[test]
fn test_struct_metadata_derive() {
    #[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, StructMetadata)]
    struct TestStruct {
        text: String,
        #[serde(serialize_with = "serialize_bigint", deserialize_with = "deserialize_bigint")]
        bigint: BigInt,
        #[serde(serialize_with = "serialize_bigdecimal", deserialize_with = "deserialize_bigdecimal")]
        bigdecimal: BigDecimal
    }

    let ts = TestStruct {
        text: "Hello!".to_string(),
        bigdecimal: BigDecimal::parse_bytes("55.77e-5".as_bytes(), 10).unwrap(),
        bigint: BigInt::parse_bytes("123".as_bytes(), 10).unwrap()
    };

    let r: Params = Params::from_struct(&ts);
    let m = r.to_struct::<TestStruct>().unwrap();
    
    assert_eq!(m.bigdecimal, BigDecimal::parse_bytes("55.77e-5".as_bytes(), 10).unwrap());
    assert_eq!(m.bigint, BigInt::parse_bytes("123".as_bytes(), 10).unwrap());
}