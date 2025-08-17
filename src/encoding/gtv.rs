//! GTV (Generic Type Value) encoding and decoding module
//! 
//! This module provides functionality for encoding and decoding GTV format, which is a flexible
//! data serialization format supporting various data types including null, boolean, integer,
//! string, arrays, dictionaries, and big integers. It uses ASN.1 encoding rules for data representation.
//! 
//! # Features
//! 
//! * Basic types: null, boolean, integer, string, byte array
//! * Complex types: arrays, dictionaries
//! * Special types: big integers, decimals
//! * Transaction encoding/decoding
//! * ASN.1-based encoding rules
//! 
//! # Examples
//! 
//! ```rust
//! // Encoding a simple value
//! let value = Params::Text("hello".to_string());
//! let encoded = encode_value(&value);
//! 
//! // Decoding a value
//! let decoded = decode(&encoded).unwrap();
//! ```

use crate::utils::{operation::{Operation, Params}, transaction::Transaction};

use asn1::{Asn1Read, Asn1Readable, Asn1Write, ParseError};
use std::collections::BTreeMap;

#[derive(Asn1Read, Asn1Write, Debug, Clone)]
pub enum Choice<'a> {
    #[explicit(0)]
    NULL(()),
    #[explicit(1)]
    OCTETSTRING(&'a [u8]),
    #[explicit(2)]
    UTF8STRING(asn1::Utf8String<'a>),
    #[explicit(3)]
    INTEGER(i64),
    #[explicit(4)]
    DICT(asn1::Sequence<'a>),
    #[explicit(5)]
    ARRAY(asn1::Sequence<'a>),
    #[explicit(6)]
    BIGINTEGER(asn1::BigInt<'a>),
}

#[derive(Debug)]
pub enum GTVType {
    Null = 0,
    ByteArray = 1,
    String = 2,
    Integer = 3,
    Dict = 4,
    Array = 5,
    BigInteger = 6,
}

pub trait GTVParams: Clone {
    fn to_writer(&self, writer: &mut asn1::Writer) -> asn1::WriteResult;
}

pub fn write_explicit_element<T: asn1::Asn1Writable>(writer: &mut asn1::Writer, val: &T, tag: u32)
  -> asn1::WriteResult {
  let tag = asn1::explicit_tag(tag);
  let content_length: Option<usize> = val.encoded_length();
  writer.write_tlv(tag, content_length, |dest| asn1::Writer::new(dest).write_element(val))
}

impl GTVParams for Params {
    fn to_writer(&self, writer: &mut asn1::Writer) -> asn1::WriteResult {
        match self {
            Params::Array(val) => {
                write_explicit_element(writer,
                    &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
                        for v in val {
                            v.to_writer(writer)?;
                        }
                        Ok(())
                    }),
                    5,
                )
            }
            Params::Dict(val) => {
                write_explicit_element(writer,
                    &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
                        for v in val {
                            writer.write_element(&asn1::SequenceWriter::new(
                                &|writer: &mut asn1::Writer| {
                                    writer.write_element(&asn1::Utf8String::new(v.0))?;
                                    v.1.to_writer(writer)?;
                                    Ok(())
                                },
                            ))?;
                        }
                        Ok(())
                    }),
                    4,
                )
            }
            Params::Integer(val) => writer.write_element(&Choice::INTEGER(*val)),
            Params::Boolean(val) => writer.write_element(&Choice::INTEGER(*val as i64)),
            Params::Decimal(val) => {
                let decimal_to_string = val.to_string();
                writer.write_element(&Choice::UTF8STRING(asn1::Utf8String::new(&decimal_to_string)))
            }
            Params::Text(val) => writer.write_element(&Choice::UTF8STRING(asn1::Utf8String::new(val))),
            Params::ByteArray(val) => writer.write_element(&Choice::OCTETSTRING(val)),
            Params::BigInteger(val) => {
                let (sign, bytes) = val.to_bytes_be();
                let bigint_to_vec_u8 = if sign == num_bigint::Sign::Minus {
                    val.to_signed_bytes_be()
                } else {
                    bytes
                };
                writer.write_element(&Choice::BIGINTEGER(asn1::BigInt::new(&bigint_to_vec_u8).unwrap()))
            }
            _ => writer.write_element(&Choice::NULL(())),
        }
    }
}

/// Encodes a transaction into a byte vector using GTV format
/// 
/// # Arguments
/// 
/// * `tx` - Reference to the Transaction to be encoded
/// 
/// # Returns
/// 
/// * `Vec<u8>` - Encoded transaction as a byte vector
pub fn encode_tx(tx: &Transaction) -> Vec<u8> {
  asn1::write(|writer| {
    write_explicit_element(writer,
      &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
          
          write_explicit_element(writer,
            &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {

              // Blockchain RID
              writer.write_element(&Choice::OCTETSTRING(
                &tx.blockchain_rid))?;

              // Operations and args
              write_explicit_element(writer,
                &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
 
                  if let Some(operations) = &tx.operations {
                    for operation in operations {
                      encode_tx_body(writer, operation)?;
                    }      
                  }

                  Ok(())
              }), 5)?;


              // Signers pubkeys
              write_explicit_element(writer,
                &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
                
                  if let Some(signers) = &tx.signers {
                    for sig in signers {
                      writer.write_element(&Choice::OCTETSTRING(sig))?;
                    }
                  }

                  Ok(())
              }), 5)?;

              Ok(())
          }), 5)?;

          // Signatures
          write_explicit_element(writer,
            &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
             
              if let Some(signatures) = &tx.signatures {
                for sig in signatures {
                  writer.write_element(&Choice::OCTETSTRING(sig))?;
                }
              }

              Ok(())
          }), 5)?;

        Ok(())
      }),
      5, )?;
    Ok(())
  }).unwrap()
}

/// Encodes a query and its arguments into GTV format
/// 
/// # Arguments
/// 
/// * `query_type` - The type of query to encode
/// * `query_args` - Optional vector of query arguments as (name, value) pairs
/// 
/// # Returns
/// 
/// * `Vec<u8>` - Encoded query as a byte vector
pub fn encode(
    query_type: &str,
    query_args: Option<&mut Vec<(&str, Params)>>,
) -> Vec<u8> {
    asn1::write(|writer| {
        write_explicit_element(writer,
            &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
                writer.write_element(&Choice::UTF8STRING(asn1::Utf8String::new(query_type)))?;
                encode_body(writer, &query_args)?;
                Ok(())
            }),
            5,
        )?;
        Ok(())
    })
    .unwrap()
}

/// Encodes the body of a transaction operation
/// 
/// # Arguments
/// 
/// * `writer` - The ASN.1 writer to write to
/// * `operation` - The operation to encode
/// 
/// # Returns
/// 
/// * `asn1::WriteResult` - Result of the write operation
fn encode_tx_body(writer: &mut asn1::Writer, operation: &Operation) -> asn1::WriteResult {
  write_explicit_element(writer, &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
    // Operation name
    write_explicit_element(writer,&asn1::Utf8String::new(operation.operation_name.as_ref().unwrap()), 2)?;
    // Operation args
    write_explicit_element(writer, &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
      if let Some(operation_args) = &operation.list {
        for arg in operation_args {
          arg.to_writer(writer)?;
        }
      } else if let Some(operation_args) = &operation.dict {
        write_explicit_element(writer, &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
          for (_key, val) in operation_args {
            val.to_writer(writer)?;
          }
          Ok(())
        }), 5)?;
      }
      Ok(())
    }), 5)?;
    Ok(())
  }), 5)
}

/// Encodes the body of a query
/// 
/// # Arguments
/// 
/// * `writer` - The ASN.1 writer to write to
/// * `query_args` - Optional query arguments to encode
/// 
/// # Returns
/// 
/// * `asn1::WriteResult` - Result of the write operation
fn encode_body(writer: &mut asn1::Writer,
  query_args: &Option<&mut Vec<(&str, Params)>>)
  -> asn1::WriteResult {
  write_explicit_element(writer,
      &asn1::SequenceWriter::new(&|writer: &mut asn1::Writer| {
          if let Some(q_args) = &query_args {
              for (q_type, q_args) in q_args.iter() {
                  writer.write_element(&asn1::SequenceWriter::new(
                      &|writer: &mut asn1::Writer| {
                          writer.write_element(&asn1::Utf8String::new(q_type))?;
                          q_args.to_writer(writer)?;
                          Ok(())
                      },
                  ))?;
              }
          }
          Ok(())
      }),
      4,
  )
}

/// Decodes a simple GTV value from a Choice enum
/// 
/// # Arguments
/// 
/// * `choice` - The Choice enum variant to decode
/// 
/// # Returns
/// 
/// * `Params` - The decoded parameter value
fn decode_simple(choice: Choice) -> Params {
  match choice {
      Choice::INTEGER(val) =>
        Params::Integer(val),
      Choice::BIGINTEGER(val) => {
        let result = if val.is_negative() {
          num_bigint::BigInt::from_signed_bytes_be(val.as_bytes())
        } else {
          num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, val.as_bytes())
        };
        Params::BigInteger(result)
      },
      Choice::OCTETSTRING(val) =>
        Params::ByteArray(val.to_vec()),
      Choice::UTF8STRING(val) =>
        Params::Text(val.as_str().to_string()),
      _ => 
        Params::Null
  }
}

/// Decodes a sequence of values into an array
/// 
/// # Arguments
/// 
/// * `parser` - The ASN.1 parser to read from
/// * `vec_array` - Vector to store the decoded values
fn decode_sequence_array<'a>(parser: &mut asn1::Parser<'a>, vec_array: &mut Vec<Params>) {
  while let Ok(val) = Choice::parse(parser) {
    let op_val = match val {
        Choice::ARRAY(seq) => {
          let res: Result<Params, ParseError> = seq.parse(|parser| {
            let mut vect_array_new: Vec<Params> = Vec::new();
            decode_sequence_array(parser, &mut vect_array_new);
            Ok(Params::Array(vect_array_new))
          });
          res.unwrap()
        }
        Choice::DICT(seq) => {
          let res: Result<Params, ParseError> = seq.parse(|parser| {
            let mut btree_map_new: BTreeMap<String, Params> = BTreeMap::new();
            decode_sequence_dict(parser, &mut btree_map_new);
            Ok(Params::Dict(btree_map_new))
          });
          res.unwrap()
        }
        _ =>
          decode_simple(val)
    };
    vec_array.push(op_val);
  }
}

/// Decodes a sequence of key-value pairs into a dictionary
/// 
/// # Arguments
/// 
/// * `parser` - The ASN.1 parser to read from
/// * `btreemap` - BTreeMap to store the decoded key-value pairs
fn decode_sequence_dict<'a>(parser: &mut asn1::Parser<'a>, btreemap: &mut BTreeMap<String, Params>) {
  while let Ok(seq) = parser.read_element::<asn1::Sequence>() {
      let res: Result<(&'a str, Params), ParseError> = seq.parse(|parser| {
        let key = parser.read_element::<asn1::Utf8String>()?;
        let val = Choice::parse(parser).unwrap();

        let op_val = match val {
          Choice::DICT(seq) => {
            let res: Result<Params, ParseError> = seq.parse(|parser| {
              let mut btree_map_new: BTreeMap<String, Params> = BTreeMap::new();
              decode_sequence_dict(parser, &mut btree_map_new);
              Ok(Params::Dict(btree_map_new))
            });
            res.unwrap()
          }
          Choice::ARRAY(seq) => {
            let res: Result<Params, ParseError> = seq.parse(|parser| {
              let mut vect_array_new: Vec<Params> = Vec::new();
              decode_sequence_array(parser, &mut vect_array_new);
              Ok(Params::Array(vect_array_new))
            });
            res.unwrap()
          },
          _ => 
            decode_simple(val)      
        };

        Ok((key.as_str(), op_val))
      });

      let (key, value) = res.unwrap();
      btreemap.insert(key.to_string(), value);
  }
}

/// Decodes a byte slice into a GTV value
/// 
/// # Arguments
/// 
/// * `data` - Byte slice containing the encoded GTV data
/// 
/// # Returns
/// 
/// * `Result<Params, ParseError>` - The decoded value or an error if decoding fails
pub fn decode(data: &[u8]) -> Result<Params, Box<ParseError>> {
  let tag = asn1::Tag::from_bytes(data).unwrap();
  let tag_num = tag.0.as_u8().unwrap() & 0x1f;

  if [0, 1, 2, 3, 6].contains(&tag_num) {
    asn1::parse(data, |d| {
        let res_choice = Choice::parse(d);
        match res_choice {
            Ok(val) => Ok(decode_simple(val)),
            Err(error) => Err(Box::new(error)),
        }
    })
  } else if tag_num == 4 {
    let result = asn1::parse_single::<asn1::Explicit<asn1::Sequence, 4>>(data).unwrap();
    result.into_inner().parse(|parser| {
      let mut btree_map_new: BTreeMap<String, Params> = BTreeMap::new();
      decode_sequence_dict(parser, &mut btree_map_new);
      Ok(Params::Dict(btree_map_new))
    })
  } else if tag_num == 5 {
    let result = asn1::parse_single::<asn1::Explicit<asn1::Sequence, 5>>(data).unwrap();
    result.into_inner().parse(|parser|{
      let mut vect_array_new: Vec<Params> = Vec::new();
      decode_sequence_array(parser, &mut vect_array_new);
      Ok(Params::Array(vect_array_new))
    })
  } else {
    Ok(Params::Null)
  }
}

/// Decodes a transaction from a byte slice
/// 
/// # Arguments
/// 
/// * `data` - Byte slice containing the encoded transaction
/// 
/// # Returns
/// 
/// * `Result<Params, Box<ParseError>>` - The decoded transaction or an error if decoding fails
pub fn decode_tx(data: &[u8]) -> Result<Params, Box<ParseError>> {
  decode(data)
}

/// Encodes a single GTV value into a byte vector
/// 
/// # Arguments
/// 
/// * `value` - The value to encode
/// 
/// # Returns
/// 
/// * `Vec<u8>` - The encoded value as a byte vector
pub fn encode_value(value: &Params) -> Vec<u8> {
  asn1::write(|writer| {
      value.to_writer(writer)?;
      Ok(())
  }).unwrap()
}

/// Encodes a GTV value and returns it as a hexadecimal string
/// 
/// # Arguments
/// 
/// * `value` - The value to encode
/// 
/// # Returns
/// 
/// * `String` - Hexadecimal representation of the encoded value
pub fn encode_value_hex_encode(value: &Params) -> String {
  hex::encode(encode_value(value))
}

/// Converts a transaction into a GTV representation for visualization
/// 
/// # Arguments
/// 
/// * `tx` - Reference to the transaction to convert
/// 
/// # Returns
/// 
/// * `Params` - GTV representation of the transaction
pub fn to_draw_gtx(tx: &Transaction) -> Params {
  let mut signers: Vec<Params> = vec![];
  let mut operations:Vec<Params> = vec![];

  if let Some(raw_signers) = &tx.signers {
    for signer in raw_signers {
      signers.push(Params::ByteArray(signer.to_vec()));
    }
  }

  for op in &tx.operations.clone().unwrap() {
    let mut op_args: Vec<Params> = vec![];

    if let Some(op_list) = &op.list {
      for arg in op_list {
        op_args.push(arg.clone());
      }
    } else if let Some(op_dict) = &op.dict {
      for (_key, value) in op_dict {
        op_args.push(value.clone());
      }
    }

    operations.push(Params::Array(vec![
      Params::Text(op.operation_name.clone().unwrap()),
      Params::Array(op_args)
    ]));
  }

  Params::Array(vec![
    Params::ByteArray(tx.blockchain_rid.to_vec()),
    Params::Array(operations),
    Params::Array(signers)
  ])
} 

#[allow(dead_code)]
/// Helper function for testing GTV encoding/decoding roundtrips
/// 
/// # Arguments
/// 
/// * `query_args` - Optional query arguments to test
/// * `expected_value` - Expected hexadecimal string after encoding
fn assert_roundtrips(
  query_args: Option<&mut Vec<(&str, Params)>>,
  expected_value: &str) {
    let result = asn1::write(|writer| {
      encode_body(writer, &query_args)?;
      Ok(())
    });
    assert_eq!(hex::encode(result.unwrap()), expected_value);
}

#[allow(dead_code)]
/// Helper function for testing GTV value encoding/decoding roundtrips
/// 
/// # Arguments
/// 
/// * `value` - Value to test
/// * `expected_decode` - Expected decoded value
/// * `expected_value` - Expected hexadecimal string after encoding
fn assert_roundtrips_value(
  value: &Params,
  expected_decode: &Params,
  expected_value: &str) {
    let encode_result = encode_value(value);
    assert_eq!(expected_value, hex::encode(encode_result.clone()));

    let decode_result = decode(&encode_result).unwrap();
    assert_eq!(expected_decode, &decode_result);
} 

#[test]
fn gtv_encode_value_null() {
  assert_roundtrips_value(&Params::Null, &Params::Null, "a0020500")
}

#[test]
fn gtv_encode_value_boolean() {
  assert_roundtrips_value(&Params::Boolean(true), &Params::Integer(1), "a303020101");
  assert_roundtrips_value(&Params::Boolean(false), &Params::Integer(0),"a303020100")
}

#[test]
fn gtv_encode_value_integer() {
  assert_roundtrips_value(&Params::Integer(999), &Params::Integer(999), "a304020203e7")
}

#[test]
fn gtv_encode_value_decimal() {
  use std::str::FromStr;
  assert_roundtrips_value(&Params::Decimal(bigdecimal::BigDecimal::from_str("999.999").unwrap()), &Params::Text("999.999".to_string()), "a2090c073939392e393939")
}

#[test]
fn gtv_encode_value_text() {
  assert_roundtrips_value(&Params::Text("hello!".to_string()), &Params::Text("hello!".to_string()), "a2080c0668656c6c6f21")
}

#[test]
fn gtv_encode_value_bytearray() {
  assert_roundtrips_value(&Params::ByteArray(b"123456789".to_vec()), &Params::ByteArray(b"123456789".to_vec()), "a10b0409313233343536373839")
}

#[test]
fn gtv_encode_value_array() {
  let array = Params::Array(vec![
          Params::Text("foo1".to_string()),
          Params::Text("foo2".to_string()),
      ]);
  assert_roundtrips_value(&array, &array, "a5123010a2060c04666f6f31a2060c04666f6f32")
}

#[test]
fn gtv_encode_value_dict() {
  use std::collections::BTreeMap;
  let mut data: BTreeMap<String, Params> = BTreeMap::new();
  let mut data1: BTreeMap<String, Params> = BTreeMap::new();
  let mut data2: BTreeMap<String, Params> = BTreeMap::new();

  data2.insert("foo1_1_1".to_string(), Params::Integer(1000));

  data1.insert("foo1_1".to_string(), Params::Dict(data2));
  data1.insert("foo1_2".to_string(), Params::Text("hello!".to_string()));

  data.insert("foo".to_string(), Params::Text("bar".to_string()));
  data.insert("foo1".to_string(), Params::Dict(data1));

  let dict = Params::Dict(data);
  assert_roundtrips_value(&dict, &dict, "a450304e300c0c03666f6fa2050c03626172303e0c04666f6f31a4363034301e0c06666f6f315f31a414301230100c08666f6f315f315f31a304020203e830120c06666f6f315f32a2080c0668656c6c6f21")
}

#[test]
fn gtv_encode_value_big_integer() {
  use std::str::FromStr;

  let max_i128: i128 = i128::MAX;
  let data = num_bigint::BigInt::from_str(max_i128.to_string().as_str()).unwrap();
  assert_roundtrips_value(&Params::BigInteger(data.clone()), &Params::BigInteger(data), "a61202107fffffffffffffffffffffffffffffff");
}

#[test]
fn gtv_test_sequence_with_empty() {
  assert_roundtrips(None, "a4023000");
}

#[test]
fn gtv_test_sequence_with_boolean() {
  assert_roundtrips(Some(&mut vec![("foo", Params::Boolean(true))]), 
  "a40e300c300a0c03666f6fa303020101");
}

#[test]
fn gtv_test_sequence_with_string() {
  assert_roundtrips(Some(&mut vec![("foo", Params::Text("bar".to_string()))]), 
  "a410300e300c0c03666f6fa2050c03626172");
}

#[test]
fn gtv_test_sequence_with_octet_string() {
  assert_roundtrips(Some(&mut vec![("foo", Params::ByteArray("bar".as_bytes().to_vec()))]), 
  "a410300e300c0c03666f6fa1050403626172");
}

#[test]
fn gtv_test_sequence_with_number() {
  assert_roundtrips(Some(&mut vec![("foo", Params::Integer(9999))]), 
  "a40f300d300b0c03666f6fa3040202270f");
}

#[test]
fn gtv_test_sequence_with_negative_number() {
  assert_roundtrips(Some(&mut vec![("foo", Params::Integer(-9999))]), 
  "a40f300d300b0c03666f6fa3040202d8f1");
}

#[test]
fn gtv_test_sequence_with_decimal() {
  use std::str::FromStr;
  assert_roundtrips(Some(&mut vec![("foo", Params::Decimal(bigdecimal::BigDecimal::from_str("99.99").unwrap()))]), 
  "a4123010300e0c03666f6fa2070c0539392e3939");
}

#[test]
fn gtv_test_sequence_with_negative_decimal() {
  use std::str::FromStr;
  assert_roundtrips(Some(&mut vec![("foo", Params::Decimal(bigdecimal::BigDecimal::from_str("-99.99").unwrap()))]),
  "a4133011300f0c03666f6fa2080c062d39392e3939");
}

#[test]
fn gtv_test_sequence_with_json() {
  let data = serde_json::json!({
            "foo": "bar",
            "bar": 9,
            "foo": 9.00
        }).to_string();
  assert_roundtrips(Some(&mut vec![("foo", Params::Text(data))]), 
  "a420301e301c0c03666f6fa2150c137b22626172223a392c22666f6f223a392e307d");
}

#[test]
fn gtv_test_sequence_with_big_integer() {
  use std::str::FromStr;

  let max_i128: i128 = i128::MAX;
  let data = num_bigint::BigInt::from_str(max_i128.to_string().as_str()).unwrap();
  assert_roundtrips(Some(&mut vec![("foo", Params::BigInteger(data))]), 
  "a41d301b30190c03666f6fa61202107fffffffffffffffffffffffffffffff");
}

#[test]
fn gtv_test_sequence_with_negative_big_integer() {
  use std::str::FromStr;

  let min_i128: i128 = i128::MIN;
  let data = num_bigint::BigInt::from_str(min_i128.to_string().as_str()).unwrap();
  assert_roundtrips(Some(&mut vec![("foo", Params::BigInteger(data))]), 
  "a41d301b30190c03666f6fa612021080000000000000000000000000000000");

  let h_data = "a41d301b30190c03666f6fa6120210ff123b1a8199614ad13ab29a33fba0eb";

  let data = num_bigint::BigInt::from_str("-1234567890123456789123456789123456789").unwrap();
  assert_roundtrips(Some(&mut vec![("foo", Params::BigInteger(data.clone()))]), 
  h_data);

  let hex_decode_data = hex::decode(h_data).unwrap();
  let result = decode(&hex_decode_data).unwrap();

  if let Params::Dict(dict) = result {
    let bi: num_bigint::BigInt = dict["foo"].clone().into();
    assert_eq!(data, bi);
  }
}

#[test]
fn gtv_test_sequence_with_array() {
  let data = &mut vec![(
      "foo",
      Params::Array(vec![
          Params::Text("bar1".to_string()),
          Params::Text("bar2".to_string()),
      ]),
  )];
  assert_roundtrips(Some(data), 
  "a41d301b30190c03666f6fa5123010a2060c0462617231a2060c0462617232");
}

#[test]
fn gtv_test_sequence_with_dict() {
  use std::collections::BTreeMap;

  let mut params: BTreeMap<String, Params> = BTreeMap::new();
  params.insert("foo".to_string(), Params::Text("bar".to_string()));
  params.insert("foo1".to_string(), Params::Text("bar1".to_string()));

  let data = &mut vec![("foo",  Params::Dict(params))];

  assert_roundtrips(Some(data), 
  "a42b302930270c03666f6fa420301e300c0c03666f6fa2050c03626172300e0c04666f6f31a2060c0462617231");
}

#[test]
fn gtv_test_sequence_with_nested_dict() {
  use std::collections::BTreeMap;

  let mut dict1: BTreeMap<String, Params> = BTreeMap::new();
  let mut dict2: BTreeMap<String, Params> = BTreeMap::new();
  let dict3: BTreeMap<String, Params> = BTreeMap::new();

  dict1.insert("dict1_foo".to_string(), Params::Text("dict1_bar".to_string()));

  dict2.insert("dict2_foo".to_string(), Params::Text("dict2_bar".to_string()));
  dict2.insert("dict2_foo1".to_string(), Params::Text("dict2_bar1".to_string()));
  
  dict2.insert("dict3_empty_data".to_string(), Params::Dict(dict3));

  dict1.insert("dict2_data".to_string(), Params::Dict(dict2));

  let data = &mut vec![("foo",  Params::Dict(dict1))];

  assert_roundtrips(Some(data), 
  "a481893081863081830c03666f6fa47c307a30180c0964696374315f666f6fa20b0c0964696374315f626172305e0c0a64696374325f64617461a450304e30180c0964696374325f666f6fa20b0c0964696374325f626172301a0c0a64696374325f666f6f31a20c0c0a64696374325f6261723130160c1064696374335f656d7074795f64617461a4023000");
}

#[test]
fn gtv_test_sequence_with_nested_dict_array() {
  use std::collections::BTreeMap;

  let mut dict1: BTreeMap<String, Params> = BTreeMap::new();
  let mut dict2: BTreeMap<String, Params> = BTreeMap::new();
  let mut dict3: BTreeMap<String, Params> = BTreeMap::new();

  dict2.insert("dict2_foo".to_string(), Params::Text("dict2_bar".to_string()));
  dict3.insert("dict3_foo".to_string(), Params::Text("dict3_bar".to_string()));

  let array1 = vec![
    Params::Dict(dict2), Params::Dict(dict3)];

  dict1.insert("array1".to_string(), Params::Array(array1));

  let data = &mut vec![("foo",  Params::Dict(dict1))];

  assert_roundtrips(Some(data), 
  "a457305530530c03666f6fa44c304a30480c06617272617931a53e303ca41c301a30180c0964696374325f666f6fa20b0c0964696374325f626172a41c301a30180c0964696374335f666f6fa20b0c0964696374335f626172");
}

#[allow(dead_code)]
/// Helper function for testing simple GTV value encoding
/// 
/// # Arguments
/// 
/// * `op` - Value to encode
/// * `expected_value` - Expected hexadecimal string after encoding
fn assert_roundtrips_simple(op: Params, expected_value: &str) {
  let result = asn1::write(|writer| {
      op.to_writer(writer)?;
      Ok(())
    });
  assert_eq!(hex::encode(result.unwrap()), expected_value);
}

#[test]
fn gtv_test_simple_null() {
  assert_roundtrips_simple(Params::Null, "a0020500");
}

#[test]
fn gtv_test_simple_boolean() {
  assert_roundtrips_simple(Params::Boolean(true), "a303020101");
  assert_roundtrips_simple(Params::Boolean(false), "a303020100");
}

#[test]
fn gtv_test_simple_integer() {
  assert_roundtrips_simple(Params::Integer(99999), "a305020301869f");
}

#[test]
fn gtv_test_simple_negative_integer_1() {
  assert_roundtrips_simple(Params::Integer(-65535), "a3050203ff0001");
}

#[test]
fn gtv_test_simple_negative_integer_2() {
  assert_roundtrips_simple(Params::Integer(-283515829), "a3060204ef19e44b");
}

#[test]
fn gtv_test_simple_big_integer() {
  assert_roundtrips_simple(Params::BigInteger(num_bigint::BigInt::from(1234567890123456789_i128)), "a60a0208112210f47de98115");
}

#[test]
fn gtv_test_simple_decimal() {
  use std::str::FromStr;
  assert_roundtrips_simple(Params::Decimal(bigdecimal::BigDecimal::from_str("99.999").unwrap()), "a2080c0639392e393939");
}

#[test]
fn gtv_test_simple_string() {
  assert_roundtrips_simple(Params::Text("abcABC123".to_string()), "a20b0c09616263414243313233");
  assert_roundtrips_simple(Params::Text("utf-8 unicode Trái Tim Ngục Tù ...!@#$%^&*()".to_string()), "a2320c307574662d3820756e69636f6465205472c3a1692054696d204e67e1bba5632054c3b9202e2e2e21402324255e262a2829");
}

#[test]
fn gtv_test_simple_byte_array() {
  assert_roundtrips_simple(Params::ByteArray(b"123456abcedf".to_vec()), "a10e040c313233343536616263656466");
}

#[test]
fn gtv_test_simple_array() {
  assert_roundtrips_simple(Params::Array(vec![
    Params::Text("foo".to_string()), Params::Integer(1)
  ]), "a50e300ca2050c03666f6fa303020101");
}

#[test]
fn gtv_test_simple_dict() {
  use std::collections::BTreeMap;
  let mut data: BTreeMap<String, Params> = BTreeMap::new();
  data.insert("foo".to_string(), Params::Text("bar".to_string()));
  assert_roundtrips_simple(Params::Dict(data), "a410300e300c0c03666f6fa2050c03626172");
}

#[allow(dead_code)]
/// Helper function for testing simple GTV value decoding
/// 
/// # Arguments
/// 
/// * `data` - Hexadecimal string to decode
/// * `expected_value` - Expected decoded value
fn assert_roundtrips_simple_decode(data: &str, expected_value: Params) {
  let hex_decode_data = hex::decode(data).unwrap();
  let result = decode(&hex_decode_data).unwrap();
  assert_eq!(result, expected_value);
}

#[test]
fn gtv_test_simple_null_decode() {
  assert_roundtrips_simple_decode("a0020500", Params::Null);
}

#[test]
fn gtv_test_simple_big_integer_decode() {
  assert_roundtrips_simple_decode("a60a0208112210f47de98115", 
    Params::BigInteger(num_bigint::BigInt::from(1234567890123456789_i128)));
}

#[test]
fn gtv_test_simple_integer_decode() {
  assert_roundtrips_simple_decode("a305020301869f", Params::Integer(99999));
}

#[test]
fn gtv_test_simple_decimal_decode() {
  assert_roundtrips_simple_decode("a2080c0639392e393939", Params::Text("99.999".to_string()));
}

#[test]
fn gtv_test_simple_string_decode() {
  assert_roundtrips_simple_decode("a2320c307574662d3820756e69636f6465205472c3a1692054696d204e67e1bba5632054c3b9202e2e2e21402324255e262a2829",
    Params::Text("utf-8 unicode Trái Tim Ngục Tù ...!@#$%^&*()".to_string()))
}

#[test]
fn gtv_test_simple_bytearray_with_hex_decode() {
  assert_roundtrips_simple_decode("a53b3039a5373035a12304210373599a61cc6b3bc02a78c34313e1737ae9cfd56b9bb24360b437d469efdf3b15a20e0c0c73616d706c655f76616c7565",
  Params::Array(vec![
    Params::Array(vec![
      Params::ByteArray(hex::decode("0373599A61CC6B3BC02A78C34313E1737AE9CFD56B9BB24360B437D469EFDF3B15").unwrap()),
      Params::Text("sample_value".to_string())
    ])
  ]))
}

#[test]
fn gtv_test_sequence_simple_array_decode() {
  let data = Params::Array(vec![
    Params::Text("foo".to_string()), Params::Integer(1),
    Params::Text("bar".to_string()), Params::Integer(2),
    Params::Array(vec![]),
    Params::Text("ca".to_string()), Params::Integer(3),
    Params::Array(vec![
      Params::Integer(1111),
      Params::Array(vec![
        Params::Integer(2222),
        Params::Integer(3333),
      ])
    ]),
  ]);

  let result = asn1::write(|writer| {
      data.to_writer(writer)?; Ok(()) }).unwrap();
  
  assert_eq!(data, decode(result.as_slice()).unwrap());
}

#[test]
fn gtv_test_sequence_simple_dict_decode() {
  let mut data_btreemap: BTreeMap<String, Params> = BTreeMap::new();

  data_btreemap.insert("foo".to_string(), Params::Text("bar".to_string()));
  data_btreemap.insert("status".to_string(), Params::ByteArray("OK".as_bytes().to_vec()));

  let data = Params::Dict(data_btreemap);

  let result = asn1::write(|writer| {
    data.to_writer(writer)?; Ok(()) }).unwrap();

  assert_eq!(data, decode(result.as_slice()).unwrap());  
}

#[test]
fn gtv_test_sequence_complex_mix_dict_array_decode() {
  use std::collections::BTreeMap;
  let mut data_btreemap: BTreeMap<String, Params> = BTreeMap::new();
  let mut dict_in: BTreeMap<String, Params> = BTreeMap::new();

  dict_in.insert("foo".to_string(), Params::Text("bar".to_string()));

  data_btreemap.insert("status".to_string(), Params::Text("dict_bar".to_string()));
  data_btreemap.insert("command".to_string(), Params::Text("dict_bar2".to_string()));
  data_btreemap.insert("state".to_string(), Params::Integer(123));
  data_btreemap.insert("dict".to_string(), Params::Dict(dict_in));
  data_btreemap.insert("array".to_string(), Params::Array(vec![
    Params::Text("test array".to_string()),
    Params::BigInteger(num_bigint::BigInt::from(123456_i128)),
    Params::Array(vec![
      Params::Text("test array 2".to_string())
    ])
  ]));
  
  let data = Params::Dict(data_btreemap);

  let result = asn1::write(|writer| {
    data.to_writer(writer)?; Ok(()) }).unwrap();

  assert_eq!(data, decode(result.as_slice()).unwrap());
}
