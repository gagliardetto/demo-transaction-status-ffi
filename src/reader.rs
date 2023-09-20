use crate::byte_order;
use crate::type_size;
use std::convert::TryInto;
use std::error::Error as StdError;

// declare error type
pub enum Error {
    ShortBuffer { msg: String },
    InvalidValue { msg: String },
    GenericError { msg: String },
}

impl StdError for Error {}

impl Error {
    pub fn short_buffer(msg: &str) -> Error {
        Error::ShortBuffer {
            msg: msg.to_string(),
        }
    }

    pub fn invalid_value(msg: &str) -> Error {
        Error::InvalidValue {
            msg: msg.to_string(),
        }
    }

    pub fn generic_error(msg: &str) -> Error {
        Error::GenericError {
            msg: msg.to_string(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::ShortBuffer { msg } => write!(f, "short buffer: {}", msg),
            Error::InvalidValue { msg } => write!(f, "invalid value: {}", msg),
            Error::GenericError { msg } => write!(f, "generic error: {}", msg),
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::ShortBuffer { msg } => write!(f, "short buffer: {}", msg),
            Error::InvalidValue { msg } => write!(f, "invalid value: {}", msg),
            Error::GenericError { msg } => write!(f, "generic error: {}", msg),
        }
    }
}

pub struct Decoder {
    data: Vec<u8>,
    pos: usize,
}

#[allow(dead_code)]
impl Decoder {
    pub fn new(data: Vec<u8>) -> Decoder {
        Decoder { data, pos: 0 }
    }

    pub fn reset(&mut self, data: Vec<u8>) {
        self.data = data;
        self.pos = 0;
    }

    pub fn read_byte(&mut self) -> Result<u8, Error> {
        if self.pos + type_size::BYTE as usize > self.data.len() {
            return Err(Error::ShortBuffer {
                msg: format!(
                    "required {} bytes, but only {} bytes available",
                    type_size::BYTE,
                    self.remaining()
                ),
            });
        }
        let b = self.data[self.pos];
        self.pos += type_size::BYTE as usize;
        Ok(b)
    }

    // 	func readNBytes(n int, reader *Decoder) ([]byte, error) {
    // 	if n == 0 {
    // 		return make([]byte, 0), nil
    // 	}
    // 	if n < 0 || n > 0x7FFF_FFFF {
    // 		return nil, fmt.Errorf("invalid length n: %v", n)
    // 	}
    // 	if reader.pos+n > len(reader.data) {
    // 		return nil, fmt.Errorf("not enough data: %d bytes missing", reader.pos+n-len(reader.data))
    // 	}
    // 	out := reader.data[reader.pos : reader.pos+n]
    // 	reader.pos += n
    // 	return out, nil
    // }

    fn read_n_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if n > 0x7FFF_FFFF {
            return Err(Error::ShortBuffer {
                msg: format!("n not valid: {}", n),
            });
        }
        if self.pos + n > self.data.len() {
            return Err(Error::ShortBuffer {
                msg: format!(
                    "required {} bytes, but only {} bytes available",
                    n,
                    self.remaining()
                ),
            });
        }
        let out = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn discard_n_bytes(&mut self, n: usize) -> Result<(), Error> {
        if n == 0 {
            return Ok(());
        }
        if n > 0x7FFF_FFFF {
            return Err(Error::ShortBuffer {
                msg: format!("n not valid: {}", n),
            });
        }
        if self.pos + n > self.data.len() {
            return Err(Error::ShortBuffer {
                msg: format!(
                    "required {} bytes, but only {} bytes available",
                    n,
                    self.remaining()
                ),
            });
        }
        self.pos += n;
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<(), Error> {
        self.discard_n_bytes(n)
    }

    pub fn discard(&mut self, n: usize) -> Result<(), Error> {
        self.discard_n_bytes(n)
    }

    // 	func (d *Decoder) Read(buf []byte) (int, error) {
    // 	if d.pos+len(buf) > len(d.data) {
    // 		return 0, io.ErrShortBuffer
    // 	}
    // 	numCopied := copy(buf, d.data[d.pos:])
    // 	d.pos += numCopied
    // 	// must read exactly len(buf) bytes
    // 	if numCopied != len(buf) {
    // 		return 0, io.ErrUnexpectedEOF
    // 	}
    // 	return len(buf), nil
    // }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.pos + buf.len() > self.data.len() {
            return Err(Error::ShortBuffer {
                msg: format!(
                    "not enough data: {} bytes missing",
                    self.pos + buf.len() - self.data.len()
                ),
            });
        }
        let num_copied = buf.len();
        buf.copy_from_slice(&self.data[self.pos..self.pos + buf.len()]);
        if num_copied != buf.len() {
            return Err(Error::ShortBuffer {
                msg: format!(
                    "expected to read {} bytes, but read only {} bytes",
                    buf.len(),
                    num_copied
                ),
            });
        }
        self.pos += num_copied;
        Ok(num_copied)
    }

    // 	// ReadBytes reads a byte slice of length n.
    // func (dec *Decoder) ReadBytes(n int) (out []byte, err error) {
    // 	return readNBytes(n, dec)
    // }

    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        self.read_n_bytes(n)
    }

    // 	func (dec *Decoder) ReadTypeID() (out TypeID, err error) {
    // 	discriminator, err := dec.ReadNBytes(8)
    // 	if err != nil {
    // 		return TypeID{}, err
    // 	}
    // 	return TypeIDFromBytes(discriminator), nil
    // }

    pub fn read_type_id(&mut self) -> Result<TypeID, Error> {
        let discriminator = self.read_n_bytes(8)?;
        Ok(TypeID::from_bytes(discriminator))
    }

    // func (dec *Decoder) ReadDiscriminator() (out TypeID, err error) {
    // 	return dec.ReadTypeID()
    // }

    pub fn read_discriminator(&mut self) -> Result<TypeID, Error> {
        self.read_type_id()
    }

    // 	func (dec *Decoder) PeekDiscriminator() (out TypeID, err error) {
    // 	discriminator, err := dec.Peek(8)
    // 	if err != nil {
    // 		return TypeID{}, err
    // 	}
    // 	return TypeIDFromBytes(discriminator), nil
    // }

    pub fn peek_discriminator(&mut self) -> Result<TypeID, Error> {
        let discriminator = self.peek(8)?;
        Ok(TypeID::from_bytes(discriminator))
    }

    // func (dec *Decoder) Peek(n int) (out []byte, err error) {
    // 	if n < 0 {
    // 		err = fmt.Errorf("n not valid: %d", n)
    // 		return
    // 	}

    // 	requiredSize := TypeSize.Byte * n
    // 	if dec.Remaining() < requiredSize {
    // 		err = fmt.Errorf("required [%d] bytes, remaining [%d]", requiredSize, dec.Remaining())
    // 		return
    // 	}

    // 	out = dec.data[dec.pos : dec.pos+n]
    // 	if traceEnabled {
    // 		zlog.Debug("decode: peek", zap.Int("n", n), zap.Binary("out", out))
    // 	}
    // 	return
    // }

    pub fn peek(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if n > 0x7FFF_FFFF {
            return Err(Error::ShortBuffer {
                msg: format!("n not valid: {}", n),
            });
        }
        if self.pos + n > self.data.len() {
            return Err(Error::ShortBuffer {
                msg: format!(
                    "required {} bytes, but only {} bytes available",
                    n,
                    self.remaining()
                ),
            });
        }
        let out = self.data[self.pos..self.pos + n].to_vec();
        Ok(out)
    }

    // 	func (dec *Decoder) ReadCompactU16() (out int, err error) {
    // 	out, size, err := DecodeCompactU16(dec.data[dec.pos:])
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read compact u16", zap.Int("val", out))
    // 	}
    // 	dec.pos += size
    // 	return out, err
    // }

    pub fn read_compact_u16(&mut self) -> Result<usize, Error> {
        let (out, size) = decode_compact_u16(&self.data[self.pos..])?;
        self.pos += size;
        Ok(out)
    }

    // 	func (dec *Decoder) ReadOption() (out bool, err error) {
    // 	b, err := dec.ReadByte()
    // 	if err != nil {
    // 		return false, fmt.Errorf("decode: read option, %w", err)
    // 	}
    // 	out = b != 0
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read option", zap.Bool("val", out))
    // 	}
    // 	return
    // }

    pub fn read_option(&mut self) -> Result<bool, Error> {
        let b = self.read_byte()?;
        let out = b != 0;
        Ok(out)
    }

    // 	func (dec *Decoder) ReadCOption() (out bool, err error) {
    // 	b, err := dec.ReadUint32(LE)
    // 	if err != nil {
    // 		return false, fmt.Errorf("decode: read c-option, %w", err)
    // 	}
    // 	if b > 1 {
    // 		return false, fmt.Errorf("decode: read c-option, invalid value: %d", b)
    // 	}
    // 	out = b != 0
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read c-option", zap.Bool("val", out))
    // 	}
    // 	return
    // }

    pub fn read_c_option(&mut self) -> Result<bool, Error> {
        let b = self.read_u32(byte_order::ByteOrder::LittleEndian)?;
        if b > 1 {
            return Err(Error::InvalidValue {
                msg: format!("invalid value: {}", b),
            });
        }
        let out = b != 0;
        Ok(out)
    }

    // 	func (dec *Decoder) ReadBool() (out bool, err error) {
    // 	if dec.Remaining() < TypeSize.Bool {
    // 		err = fmt.Errorf("bool required [%d] byte, remaining [%d]", TypeSize.Bool, dec.Remaining())
    // 		return
    // 	}

    // 	b, err := dec.ReadByte()
    // 	if err != nil {
    // 		err = fmt.Errorf("readBool, %s", err)
    // 	}
    // 	out = b != 0
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read bool", zap.Bool("val", out))
    // 	}
    // 	return
    // }

    pub fn read_bool(&mut self) -> Result<bool, Error> {
        if self.remaining() < type_size::BOOL {
            return Err(Error::InvalidValue {
                msg: format!(
                    "bool requires [{}] bytes, remaining [{}]",
                    type_size::BOOL,
                    self.remaining()
                ),
            });
        }
        let b = self.read_byte()?;
        let out = b != 0;
        Ok(out)
    }

    // 	func (dec *Decoder) ReadUint8() (out uint8, err error) {
    // 	out, err = dec.ReadByte()
    // 	return
    // }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let out = self.read_byte()?;
        Ok(out)
    }

    // 	func (dec *Decoder) ReadInt8() (out int8, err error) {
    // 	b, err := dec.ReadByte()
    // 	out = int8(b)
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read int8", zap.Int8("val", out))
    // 	}
    // 	return
    // }

    pub fn read_i8(&mut self) -> Result<i8, Error> {
        let b = self.read_byte()?;
        let out = b as i8; // TODO: check this
        Ok(out)
    }

    // 	func (dec *Decoder) ReadUint16(order binary.ByteOrder) (out uint16, err error) {
    // 	if dec.Remaining() < TypeSize.Uint16 {
    // 		err = fmt.Errorf("uint16 required [%d] bytes, remaining [%d]", TypeSize.Uint16, dec.Remaining())
    // 		return
    // 	}

    // 	out = order.Uint16(dec.data[dec.pos:])
    // 	dec.pos += TypeSize.Uint16
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read uint16", zap.Uint16("val", out))
    // 	}
    // 	return
    // }

    pub fn read_u16(&mut self, order: byte_order::ByteOrder) -> Result<u16, Error> {
        if self.remaining() < type_size::UINT16 {
            return Err(Error::InvalidValue {
                msg: format!(
                    "uint16 requires [{}] bytes, remaining [{}]",
                    type_size::UINT16,
                    self.remaining()
                ),
            });
        }
        let buf = self.read_bytes(type_size::UINT16)?;
        let buf: [u8; 2] = buf.try_into().unwrap();
        let out = match order {
            byte_order::ByteOrder::LittleEndian => u16::from_le_bytes(buf),
            byte_order::ByteOrder::BigEndian => u16::from_be_bytes(buf),
        };
        Ok(out)
    }

    // 	func (dec *Decoder) ReadInt16(order binary.ByteOrder) (out int16, err error) {
    // 	n, err := dec.ReadUint16(order)
    // 	out = int16(n)
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read int16", zap.Int16("val", out))
    // 	}
    // 	return
    // }

    pub fn read_i16(&mut self, order: byte_order::ByteOrder) -> Result<i16, Error> {
        let n = self.read_u16(order)?;
        Ok(n as i16)
    }

    // 	func (dec *Decoder) ReadUint32(order binary.ByteOrder) (out uint32, err error) {
    // 	if dec.Remaining() < TypeSize.Uint32 {
    // 		err = fmt.Errorf("uint32 required [%d] bytes, remaining [%d]", TypeSize.Uint32, dec.Remaining())
    // 		return
    // 	}

    // 	out = order.Uint32(dec.data[dec.pos:])
    // 	dec.pos += TypeSize.Uint32
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read uint32", zap.Uint32("val", out))
    // 	}
    // 	return
    // }

    pub fn read_u32(&mut self, order: byte_order::ByteOrder) -> Result<u32, Error> {
        if self.remaining() < type_size::UINT32 {
            return Err(Error::InvalidValue {
                msg: format!(
                    "uint32 requires [{}] bytes, remaining [{}]",
                    type_size::UINT32,
                    self.remaining()
                ),
            });
        }
        let buf = self.read_bytes(type_size::UINT32)?;
        let buf: [u8; 4] = buf.try_into().unwrap();
        let out = match order {
            byte_order::ByteOrder::LittleEndian => u32::from_le_bytes(buf),
            byte_order::ByteOrder::BigEndian => u32::from_be_bytes(buf),
        };
        Ok(out)
    }

    // 	func (dec *Decoder) ReadInt32(order binary.ByteOrder) (out int32, err error) {
    // 	n, err := dec.ReadUint32(order)
    // 	out = int32(n)
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read int32", zap.Int32("val", out))
    // 	}
    // 	return
    // }

    pub fn read_i32(&mut self, order: byte_order::ByteOrder) -> Result<i32, Error> {
        let n = self.read_u32(order)?;
        Ok(n as i32)
    }

    // func (dec *Decoder) ReadUint64(order binary.ByteOrder) (out uint64, err error) {
    // 	if dec.Remaining() < TypeSize.Uint64 {
    // 		err = fmt.Errorf("decode: uint64 required [%d] bytes, remaining [%d]", TypeSize.Uint64, dec.Remaining())
    // 		return
    // 	}

    // 	data, err := dec.ReadNBytes(TypeSize.Uint64)
    // 	if err != nil {
    // 		return 0, err
    // 	}
    // 	out = order.Uint64(data)
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read uint64", zap.Uint64("val", out), zap.Stringer("hex", HexBytes(data)))
    // 	}
    // 	return
    // }

    pub fn read_u64(&mut self, order: byte_order::ByteOrder) -> Result<u64, Error> {
        if self.remaining() < type_size::UINT64 {
            return Err(Error::InvalidValue {
                msg: format!(
                    "uint64 requires [{}] bytes, remaining [{}]",
                    type_size::UINT64,
                    self.remaining()
                ),
            });
        }
        let buf = self.read_bytes(type_size::UINT64)?;
        let buf: [u8; 8] = buf.try_into().unwrap();
        let out = match order {
            byte_order::ByteOrder::LittleEndian => u64::from_le_bytes(buf),
            byte_order::ByteOrder::BigEndian => u64::from_be_bytes(buf),
        };
        Ok(out)
    }

    // 	func (dec *Decoder) ReadInt64(order binary.ByteOrder) (out int64, err error) {
    // 	n, err := dec.ReadUint64(order)
    // 	out = int64(n)
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read int64", zap.Int64("val", out))
    // 	}
    // 	return
    // }

    pub fn read_i64(&mut self, order: byte_order::ByteOrder) -> Result<i64, Error> {
        let n = self.read_u64(order)?;
        Ok(n as i64)
    }

    // 	func (dec *Decoder) ReadUint128(order binary.ByteOrder) (out Uint128, err error) {
    // 	if dec.Remaining() < TypeSize.Uint128 {
    // 		err = fmt.Errorf("uint128 required [%d] bytes, remaining [%d]", TypeSize.Uint128, dec.Remaining())
    // 		return
    // 	}

    // 	data := dec.data[dec.pos : dec.pos+TypeSize.Uint128]

    // 	if order == binary.LittleEndian {
    // 		out.Hi = order.Uint64(data[8:])
    // 		out.Lo = order.Uint64(data[:8])
    // 	} else {
    // 		// TODO: is this correct?
    // 		out.Hi = order.Uint64(data[:8])
    // 		out.Lo = order.Uint64(data[8:])
    // 	}

    // 	dec.pos += TypeSize.Uint128
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read uint128", zap.Stringer("hex", out), zap.Uint64("hi", out.Hi), zap.Uint64("lo", out.Lo))
    // 	}
    // 	return
    // }

    pub fn read_u128(&mut self, order: byte_order::ByteOrder) -> Result<u128, Error> {
        if self.remaining() < type_size::UINT128 {
            return Err(Error::InvalidValue {
                msg: format!(
                    "uint128 requires [{}] bytes, remaining [{}]",
                    type_size::UINT128,
                    self.remaining()
                ),
            });
        }
        let buf = self.read_bytes(type_size::UINT128)?;
        let buf: [u8; 16] = buf.try_into().unwrap();
        let out = match order {
            byte_order::ByteOrder::LittleEndian => u128::from_le_bytes(buf),
            byte_order::ByteOrder::BigEndian => u128::from_be_bytes(buf),
        };
        Ok(out)
    }

    // 	func (dec *Decoder) ReadInt128(order binary.ByteOrder) (out Int128, err error) {
    // 	v, err := dec.ReadUint128(order)
    // 	if err != nil {
    // 		return
    // 	}
    // 	return Int128(v), nil
    // }

    pub fn read_i128(&mut self, order: byte_order::ByteOrder) -> Result<i128, Error> {
        let n = self.read_u128(order)?;
        Ok(n as i128)
    }

    // 	func (dec *Decoder) ReadFloat32(order binary.ByteOrder) (out float32, err error) {
    // 	if dec.Remaining() < TypeSize.Float32 {
    // 		err = fmt.Errorf("float32 required [%d] bytes, remaining [%d]", TypeSize.Float32, dec.Remaining())
    // 		return
    // 	}

    // 	n := order.Uint32(dec.data[dec.pos:])
    // 	out = math.Float32frombits(n)
    // 	dec.pos += TypeSize.Float32
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read float32", zap.Float32("val", out))
    // 	}

    // 	if dec.IsBorsh() {
    // 		if math.IsNaN(float64(out)) {
    // 			return 0, errors.New("NaN for float not allowed")
    // 		}
    // 	}
    // 	return
    // }

    pub fn read_f32(&mut self, order: byte_order::ByteOrder) -> Result<f32, Error> {
        if self.remaining() < type_size::FLOAT32 {
            return Err(Error::InvalidValue {
                msg: format!(
                    "float32 requires [{}] bytes, remaining [{}]",
                    type_size::FLOAT32,
                    self.remaining()
                ),
            });
        }
        let buf = self.read_bytes(type_size::FLOAT32)?;
        let buf: [u8; 4] = buf.try_into().unwrap();
        let out = match order {
            byte_order::ByteOrder::LittleEndian => f32::from_le_bytes(buf),
            byte_order::ByteOrder::BigEndian => f32::from_be_bytes(buf),
        };
        Ok(out)
    }

    // func (dec *Decoder) ReadFloat64(order binary.ByteOrder) (out float64, err error) {
    // 	if dec.Remaining() < TypeSize.Float64 {
    // 		err = fmt.Errorf("float64 required [%d] bytes, remaining [%d]", TypeSize.Float64, dec.Remaining())
    // 		return
    // 	}

    // 	n := order.Uint64(dec.data[dec.pos:])
    // 	out = math.Float64frombits(n)
    // 	dec.pos += TypeSize.Float64
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read Float64", zap.Float64("val", out))
    // 	}
    // 	if dec.IsBorsh() {
    // 		if math.IsNaN(out) {
    // 			return 0, errors.New("NaN for float not allowed")
    // 		}
    // 	}
    // 	return
    // }

    pub fn read_f64(&mut self, order: byte_order::ByteOrder) -> Result<f64, Error> {
        if self.remaining() < type_size::FLOAT64 {
            return Err(Error::InvalidValue {
                msg: format!(
                    "float64 requires [{}] bytes, remaining [{}]",
                    type_size::FLOAT64,
                    self.remaining()
                ),
            });
        }
        let buf = self.read_bytes(type_size::FLOAT64)?;
        let buf: [u8; 8] = buf.try_into().unwrap();
        let out = match order {
            byte_order::ByteOrder::LittleEndian => f64::from_le_bytes(buf),
            byte_order::ByteOrder::BigEndian => f64::from_be_bytes(buf),
        };
        Ok(out)
    }

    // 	func (dec *Decoder) ReadByteSlice() (out []byte, err error) {
    // 	length, err := dec.ReadUint32()
    // 	if err != nil {
    // 		return nil, err
    // 	}

    // 	if len(dec.data) < dec.pos+length {
    // 		return nil, fmt.Errorf("byte array: varlen=%d, missing %d bytes", length, dec.pos+length-len(dec.data))
    // 	}

    // 	out = dec.data[dec.pos : dec.pos+length]
    // 	dec.pos += length
    // 	if traceEnabled {
    // 		zlog.Debug("decode: read byte array", zap.Stringer("hex", HexBytes(out)))
    // 	}
    // 	return
    // }

    pub fn read_byte_slice(&mut self) -> Result<Vec<u8>, Error> {
        let length = self.read_u32(byte_order::ByteOrder::LittleEndian)?;
        if self.data.len() < self.pos + length as usize {
            return Err(Error::InvalidValue {
                msg: format!(
                    "byte array: required {} bytes, but only {} bytes available",
                    length,
                    self.remaining()
                ),
            });
        }
        let out = self.data[self.pos..self.pos + length as usize].to_vec();
        self.pos += length as usize;
        Ok(out)
    }

    // 	func (dec *Decoder) ReadString() (out string, err error) {
    // 	data, err := dec.ReadByteSlice()
    // 	out = string(data)
    // 	if traceEnabled {
    // 		zlog.Debug("read string", zap.String("val", out))
    // 	}
    // 	return
    // }

    pub fn read_string(&mut self) -> Result<String, Error> {
        let data = self.read_byte_slice()?;
        let out = String::from_utf8(data);
        match out {
            Ok(out) => Ok(out),
            Err(e) => Err(Error::InvalidValue {
                msg: format!("invalid utf8 string: {}", e),
            }),
        }
    }

    // 	func (dec *Decoder) SetPosition(idx uint) error {
    // 	if int(idx) < len(dec.data) {
    // 		dec.pos = int(idx)
    // 		return nil
    // 	}
    // 	return fmt.Errorf("request to set position to %d outsize of buffer (buffer size %d)", idx, len(dec.data))
    // }

    pub fn set_position(&mut self, idx: usize) -> Result<(), Error> {
        if idx < self.data.len() {
            self.pos = idx;
            Ok(())
        } else {
            Err(Error::InvalidValue {
                msg: format!(
                    "request to set position to {} outsize of buffer (buffer size {})",
                    idx,
                    self.data.len()
                ),
            })
        }
    }

    // 	func (dec *Decoder) Position() uint {
    // 	return uint(dec.pos)
    // }

    pub fn position(&self) -> usize {
        self.pos
    }

    // 	func (dec *Decoder) Len() int {
    // 	return len(dec.data)
    // }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    // 	func (dec *Decoder) HasRemaining() bool {
    // 	return dec.Remaining() > 0
    // }

    pub fn has_remaining(&self) -> bool {
        self.remaining() > 0
    }
}

// declare TypeID as a [u8; 8]
pub type TypeID = [u8; 8];

// use extension trait to add a method to the TypeID type
pub trait TypeIDFromBytes {
    fn from_bytes(bytes: Vec<u8>) -> TypeID;
}

impl TypeIDFromBytes for TypeID {
    fn from_bytes(bytes: Vec<u8>) -> TypeID {
        let mut type_id = [0u8; 8];
        type_id.copy_from_slice(&bytes);
        type_id
    }
}

// 	func DecodeCompactU16(bytes []byte) (int, int, error) {
// 	ln := 0
// 	size := 0
// 	for {
// 		if len(bytes) == 0 {
// 			return 0, 0, io.ErrUnexpectedEOF
// 		}
// 		elem := int(bytes[0])
// 		bytes = bytes[1:]
// 		ln |= (elem & 0x7f) << (size * 7)
// 		size += 1
// 		if (elem & 0x80) == 0 {
// 			break
// 		}
// 	}
// 	return ln, size, nil
// }

pub fn decode_compact_u16(bytes: &[u8]) -> Result<(usize, usize), Error> {
    let mut ln = 0;
    let mut size = 0;
    for elem in bytes {
        ln |= (usize::from(*elem) & 0x7F) << (size * 7);
        size += 1;
        if (usize::from(*elem) & 0x80) == 0 {
            break;
        }
    }
    Ok((ln, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    // func TestDecoder_Peek(t *testing.T) {
    // 	buf := []byte{
    // 		0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0,
    // 	}

    // 	dec := NewBinDecoder(buf)
    // 	{
    // 		peeked, err := dec.Peek(8)
    // 		assert.NoError(t, err)
    // 		assert.Len(t, peeked, 8)
    // 		assert.Equal(t, buf, peeked)
    // 	}
    // 	{
    // 		peeked, err := dec.Peek(8)
    // 		assert.NoError(t, err)
    // 		assert.Len(t, peeked, 8)
    // 		assert.Equal(t, buf, peeked)
    // 	}
    // 	{
    // 		peeked, err := dec.Peek(1)
    // 		assert.NoError(t, err)
    // 		assert.Len(t, peeked, 1)
    // 		assert.Equal(t, buf[0], peeked[0])
    // 	}
    // 	{
    // 		peeked, err := dec.Peek(2)
    // 		assert.NoError(t, err)
    // 		assert.Len(t, peeked, 2)
    // 		assert.Equal(t, buf[:2], peeked)
    // 	}
    // 	{
    // 		read, err := dec.ReadByte()
    // 		assert.Equal(t, buf[0], read)
    // 		assert.NoError(t, err)

    // 		peeked, err := dec.Peek(1)
    // 		assert.NoError(t, err)
    // 		assert.Len(t, peeked, 1)
    // 		assert.Equal(t, buf[1], peeked[0])
    // 	}
    // }

    #[test]
    fn test_decoder_peek() {
        let original = vec![0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0];
        let buf = original.clone();

        let mut dec = Decoder::new(original);
        {
            let peeked = dec.peek(8).unwrap();
            assert_eq!(buf, peeked);
        }
        {
            let peeked = dec.peek(8).unwrap();
            assert_eq!(buf, peeked);
        }
        {
            let peeked = dec.peek(1).unwrap();
            assert_eq!(buf[0], peeked[0]);
        }
        {
            let peeked = dec.peek(2).unwrap();
            assert_eq!(buf[0..2], peeked);
        }
        {
            let read = dec.read_byte().unwrap();
            assert_eq!(buf[0], read);

            let peeked = dec.peek(1).unwrap();
            assert_eq!(buf[1], peeked[0]);
        }
    }

    // 	func TestDecoder_Remaining(t *testing.T) {
    // 	b := make([]byte, 4)
    // 	binary.LittleEndian.PutUint16(b, 1)
    // 	binary.LittleEndian.PutUint16(b[2:], 2)

    // 	d := NewBinDecoder(b)

    // 	n, err := d.ReadUint16(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint16(1), n)
    // 	assert.Equal(t, 2, d.Remaining())

    // 	n, err = d.ReadUint16(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint16(2), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_remaining() {
        let mut b = vec![0u8; 4];
        b[0..2].copy_from_slice(&1u16.to_le_bytes());
        b[2..4].copy_from_slice(&2u16.to_le_bytes());

        assert_eq!(b, vec![1, 0, 2, 0]);

        let mut d = Decoder::new(b);

        assert_eq!(0, d.pos);
        let n = d.read_u16(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(1, n);
        assert_eq!(2, d.pos);
        assert_eq!(2, d.remaining());

        let n = d.read_u16(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(2, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_int8(t *testing.T) {
    // 	buf := []byte{
    // 		0x9d, // -99
    // 		0x64, // 100
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadInt8()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int8(-99), n)
    // 	assert.Equal(t, 1, d.Remaining())

    // 	n, err = d.ReadInt8()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int8(100), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_int8() {
        let buf = vec![0x9d, 0x64];

        let mut d = Decoder::new(buf);

        let n = d.read_i8().unwrap();
        assert_eq!(-99, n);
        assert_eq!(1, d.remaining());

        let n = d.read_i8().unwrap();
        assert_eq!(100, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_int16(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0xae, 0xff, // -82
    // 		0x49, 0x00, // 73
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadInt16(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int16(-82), n)
    // 	assert.Equal(t, 2, d.Remaining())

    // 	n, err = d.ReadInt16(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int16(73), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0xff, 0xae, // -82
    // 		0x00, 0x49, // 73
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadInt16(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int16(-82), n)
    // 	assert.Equal(t, 2, d.Remaining())

    // 	n, err = d.ReadInt16(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int16(73), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_int16() {
        // little endian
        let buf = vec![0xae, 0xff, 0x49, 0x00];

        let mut d = Decoder::new(buf);

        let n = d.read_i16(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(-82, n);
        assert_eq!(2, d.remaining());

        let n = d.read_i16(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(73, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![0xff, 0xae, 0x00, 0x49];

        let mut d = Decoder::new(buf);

        let n = d.read_i16(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(-82, n);
        assert_eq!(2, d.remaining());

        let n = d.read_i16(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(73, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_int32(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0xd8, 0x8d, 0x8a, 0xef, // -276132392
    // 		0x4f, 0x9f, 0x3, 0x00, // 237391
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadInt32(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int32(-276132392), n)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	n, err = d.ReadInt32(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int32(237391), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0xef, 0x8a, 0x8d, 0xd8, // -276132392
    // 		0x00, 0x3, 0x9f, 0x4f, // 237391
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadInt32(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int32(-276132392), n)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	n, err = d.ReadInt32(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int32(237391), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_int32() {
        // little endian
        let buf = vec![0xd8, 0x8d, 0x8a, 0xef, 0x4f, 0x9f, 0x3, 0x00];

        let mut d = Decoder::new(buf);

        let n = d.read_i32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(-276132392, n);
        assert_eq!(4, d.remaining());

        let n = d.read_i32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(237391, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![0xef, 0x8a, 0x8d, 0xd8, 0x00, 0x3, 0x9f, 0x4f];

        let mut d = Decoder::new(buf);

        let n = d.read_i32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(-276132392, n);
        assert_eq!(4, d.remaining());

        let n = d.read_i32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(237391, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_int64(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x91, 0x7d, 0xf3, 0xff, 0xff, 0xff, 0xff, 0xff, //-819823
    // 		0xe3, 0x1c, 0x1, 0x00, 0x00, 0x00, 0x00, 0x00, //72931
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadInt64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(-819823), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadInt64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(72931), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0xff, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x7d, 0x91, //-819823
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x1, 0x1c, 0xe3, //72931
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadInt64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(-819823), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadInt64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(72931), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_int64() {
        // little endian
        let buf = vec![
            0x91, 0x7d, 0xf3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe3, 0x1c, 0x1, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut d = Decoder::new(buf);

        let n = d.read_i64(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(-819823, n);
        assert_eq!(8, d.remaining());

        let n = d.read_i64(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(72931, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x7d, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1,
            0x1c, 0xe3,
        ];

        let mut d = Decoder::new(buf);

        let n = d.read_i64(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(-819823, n);
        assert_eq!(8, d.remaining());

        let n = d.read_i64(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(72931, n);
        assert_eq!(0, d.remaining());
    }

    // func TestDecoder_uint8(t *testing.T) {
    // 	buf := []byte{
    // 		0x63, // 99
    // 		0x64, // 100
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadUint8()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint8(99), n)
    // 	assert.Equal(t, 1, d.Remaining())

    // 	n, err = d.ReadUint8()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint8(100), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_uint8() {
        let buf = vec![0x63, 0x64];

        let mut d = Decoder::new(buf);

        let n = d.read_u8().unwrap();
        assert_eq!(99, n);
        assert_eq!(1, d.remaining());

        let n = d.read_u8().unwrap();
        assert_eq!(100, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_uint16(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x52, 0x00, // 82
    // 		0x49, 0x00, // 73
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadUint16(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint16(82), n)
    // 	assert.Equal(t, 2, d.Remaining())

    // 	n, err = d.ReadUint16(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint16(73), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0x00, 0x52, // 82
    // 		0x00, 0x49, // 73
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadUint16(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint16(82), n)
    // 	assert.Equal(t, 2, d.Remaining())

    // 	n, err = d.ReadUint16(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint16(73), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_uint16() {
        // little endian
        let buf = vec![0x52, 0x00, 0x49, 0x00];

        let mut d = Decoder::new(buf);

        let n = d.read_u16(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(82, n);
        assert_eq!(2, d.remaining());

        let n = d.read_u16(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(73, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![0x00, 0x52, 0x00, 0x49];

        let mut d = Decoder::new(buf);

        let n = d.read_u16(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(82, n);
        assert_eq!(2, d.remaining());

        let n = d.read_u16(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(73, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_uint32(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x28, 0x72, 0x75, 0x10, // 276132392 as LE
    // 		0x4f, 0x9f, 0x03, 0x00, // 237391 as LE
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadUint32(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint32(276132392), n)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	n, err = d.ReadUint32(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint32(237391), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0x10, 0x75, 0x72, 0x28, // 276132392 as LE
    // 		0x00, 0x03, 0x9f, 0x4f, // 237391 as LE
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadUint32(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint32(276132392), n)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	n, err = d.ReadUint32(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint32(237391), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_uint32() {
        // little endian
        let buf = vec![0x28, 0x72, 0x75, 0x10, 0x4f, 0x9f, 0x03, 0x00];

        let mut d = Decoder::new(buf);

        let n = d.read_u32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(276132392, n);
        assert_eq!(4, d.remaining());

        let n = d.read_u32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(237391, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![0x10, 0x75, 0x72, 0x28, 0x00, 0x03, 0x9f, 0x4f];

        let mut d = Decoder::new(buf);

        let n = d.read_u32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(276132392, n);
        assert_eq!(4, d.remaining());

        let n = d.read_u32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(237391, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_uint64(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x6f, 0x82, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, //819823
    // 		0xe3, 0x1c, 0x1, 0x00, 0x00, 0x00, 0x00, 0x00, //72931
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadUint64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint64(819823), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadUint64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint64(72931), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x82, 0x6f, //819823
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x1, 0x1c, 0xe3, //72931
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadUint64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint64(819823), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadUint64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, uint64(72931), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_uint64() {
        // little endian
        let buf = vec![
            0x6f, 0x82, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe3, 0x1c, 0x1, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut d = Decoder::new(buf);

        let n = d.read_u64(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(819823, n);
        assert_eq!(8, d.remaining());

        let n = d.read_u64(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(72931, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x82, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1,
            0x1c, 0xe3,
        ];

        let mut d = Decoder::new(buf);

        let n = d.read_u64(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(819823, n);
        assert_eq!(8, d.remaining());

        let n = d.read_u64(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(72931, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_float32(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0xc3, 0xf5, 0xa8, 0x3f,
    // 		0xa4, 0x70, 0x4d, 0xc0,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadFloat32(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float32(1.32), n)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	n, err = d.ReadFloat32(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float32(-3.21), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0x3f, 0xa8, 0xf5, 0xc3,
    // 		0xc0, 0x4d, 0x70, 0xa4,
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadFloat32(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float32(1.32), n)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	n, err = d.ReadFloat32(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float32(-3.21), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_float32() {
        // little endian
        let buf = vec![0xc3, 0xf5, 0xa8, 0x3f, 0xa4, 0x70, 0x4d, 0xc0];

        let mut d = Decoder::new(buf);

        let n = d.read_f32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(1.32, n);
        assert_eq!(4, d.remaining());

        let n = d.read_f32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(-3.21, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![0x3f, 0xa8, 0xf5, 0xc3, 0xc0, 0x4d, 0x70, 0xa4];

        let mut d = Decoder::new(buf);

        let n = d.read_f32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(1.32, n);
        assert_eq!(4, d.remaining());

        let n = d.read_f32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(-3.21, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_float64(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x3d, 0x0a, 0xd7, 0xa3, 0x70, 0x1d, 0x4f, 0xc0,
    // 		0x77, 0xbe, 0x9f, 0x1a, 0x2f, 0x3d, 0x37, 0x40,
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f,
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff,
    // 		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x7f,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadFloat64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float64(-62.23), n)
    // 	assert.Equal(t, 32, d.Remaining())

    // 	n, err = d.ReadFloat64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float64(23.239), n)
    // 	assert.Equal(t, 24, d.Remaining())

    // 	n, err = d.ReadFloat64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, math.Inf(1), n)
    // 	assert.Equal(t, 16, d.Remaining())

    // 	n, err = d.ReadFloat64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, math.Inf(-1), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadFloat64(LE)
    // 	assert.NoError(t, err)
    // 	assert.True(t, math.IsNaN(n))

    // 	// big endian
    // 	buf = []byte{
    // 		0xc0, 0x4f, 0x1d, 0x70, 0xa3, 0xd7, 0x0a, 0x3d,
    // 		0x40, 0x37, 0x3d, 0x2f, 0x1a, 0x9f, 0xbe, 0x77,
    // 		0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 		0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 		0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadFloat64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float64(-62.23), n)
    // 	assert.Equal(t, 32, d.Remaining())

    // 	n, err = d.ReadFloat64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, float64(23.239), n)
    // 	assert.Equal(t, 24, d.Remaining())

    // 	n, err = d.ReadFloat64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, math.Inf(1), n)
    // 	assert.Equal(t, 16, d.Remaining())

    // 	n, err = d.ReadFloat64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, math.Inf(-1), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadFloat64(BE)
    // 	assert.NoError(t, err)
    // 	assert.True(t, math.IsNaN(n))
    // }

    #[test]
    fn test_decoder_float64() {
        // little endian
        let buf = vec![0xc3, 0xf5, 0xa8, 0x3f, 0xa4, 0x70, 0x4d, 0xc0];

        let mut d = Decoder::new(buf);

        let n = d.read_f32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(1.32, n);
        assert_eq!(4, d.remaining());

        let n = d.read_f32(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(-3.21, n);
        assert_eq!(0, d.remaining());

        // big endian
        let buf = vec![0x3f, 0xa8, 0xf5, 0xc3, 0xc0, 0x4d, 0x70, 0xa4];

        let mut d = Decoder::new(buf);

        let n = d.read_f32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(1.32, n);
        assert_eq!(4, d.remaining());

        let n = d.read_f32(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(-3.21, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_string(t *testing.T) {
    // 	buf := []byte{
    // 		0x03, 0x31, 0x32, 0x33, // "123"
    // 		0x00,                   // ""
    // 		0x03, 0x61, 0x62, 0x63, // "abc
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	s, err := d.ReadString()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, "123", s)
    // 	assert.Equal(t, 5, d.Remaining())

    // 	s, err = d.ReadString()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, "", s)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	s, err = d.ReadString()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, "abc", s)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_string() {
        let mut buf = vec![];
        buf.extend_from_slice(u32::to_le_bytes(3).as_ref());
        buf.extend_from_slice(&[0x31, 0x32, 0x33]); // "123"
        buf.extend_from_slice(u32::to_le_bytes(0).as_ref());
        buf.extend_from_slice(u32::to_le_bytes(3).as_ref());
        buf.extend_from_slice(&[0x61, 0x62, 0x63]); // "abc"

        let mut d = Decoder::new(buf);

        let s = d.read_string().unwrap();
        assert_eq!("123", s);
        assert_eq!(11, d.remaining());

        let s = d.read_string().unwrap();
        assert_eq!("", s);
        assert_eq!(7, d.remaining());

        let s = d.read_string().unwrap();
        assert_eq!("abc", s);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_Decode_String_Err(t *testing.T) {
    // 	buf := []byte{
    // 		0x01, 0x00, 0x00, 0x00,
    // 		byte('a'),
    // 	}

    // 	decoder := NewBinDecoder(buf)

    // 	s, err := decoder.ReadString()
    // 	assert.EqualError(t, err, "decode: uint64 required [8] bytes, remaining [5]")
    // }

    #[test]
    fn test_decoder_decode_string_err() {
        let buf = vec![0x05, 0x00, 0x00, 0x00, 0x61];

        let mut decoder = Decoder::new(buf);

        let s = decoder.read_string();
        assert!(s.is_err());
    }

    // 	func TestDecoder_Byte(t *testing.T) {
    // 	buf := []byte{
    // 		0x00, 0x01,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadByte()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, byte(0), n)
    // 	assert.Equal(t, 1, d.Remaining())

    // 	n, err = d.ReadByte()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, byte(1), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_byte() {
        let buf = vec![0x00, 0x01];

        let mut d = Decoder::new(buf);

        let n = d.read_byte().unwrap();
        assert_eq!(0, n);
        assert_eq!(1, d.remaining());

        let n = d.read_byte().unwrap();
        assert_eq!(1, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_Bool(t *testing.T) {
    // 	buf := []byte{
    // 		0x01, 0x00,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadBool()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, true, n)
    // 	assert.Equal(t, 1, d.Remaining())

    // 	n, err = d.ReadBool()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, false, n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_bool() {
        let buf = vec![0x01, 0x00];

        let mut d = Decoder::new(buf);

        let n = d.read_bool().unwrap();
        assert_eq!(true, n);
        assert_eq!(1, d.remaining());

        let n = d.read_bool().unwrap();
        assert_eq!(false, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_ByteArray(t *testing.T) {
    // 	buf := []byte{
    // 		0x03, 0x01, 0x02, 0x03,
    // 		0x03, 0x04, 0x05, 0x06,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	data, err := d.ReadByteSlice()
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, []byte{1, 2, 3}, data)
    // 	assert.Equal(t, 4, d.Remaining())

    // 	data, err = d.ReadByteSlice()
    // 	assert.Equal(t, []byte{4, 5, 6}, data)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_byte_array() {
        let mut buf = vec![];
        buf.extend_from_slice(u32::to_le_bytes(3).as_ref());
        buf.extend_from_slice(&[0x01, 0x02, 0x03]);
        buf.extend_from_slice(u32::to_le_bytes(3).as_ref());
        buf.extend_from_slice(&[0x04, 0x05, 0x06]);

        let mut d = Decoder::new(buf);

        let data = d.read_byte_slice().unwrap();
        assert_eq!(vec![1, 2, 3], data);
        assert_eq!(7, d.remaining());

        let data = d.read_byte_slice().unwrap();
        assert_eq!(vec![4, 5, 6], data);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_ByteArray_MissingData(t *testing.T) {
    // 	buf := []byte{
    // 		0x0a,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	_, err := d.ReadByteSlice()
    // 	assert.EqualError(t, err, "byte array: varlen=10, missing 10 bytes")
    // }

    #[test]
    fn test_decoder_byte_array_missing_data() {
        let buf = vec![0x0a];

        let mut d = Decoder::new(buf);

        let data = d.read_byte_slice();
        assert!(data.is_err());
    }

    // 	func TestDecoder_ByteArray_InvalidLength(t *testing.T) {
    // 	buf := []byte{
    // 		0x01, 0x00, 0x00, 0x00,
    // 		0x01, 0x02,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	_, err := d.ReadByteSlice()
    // 	assert.EqualError(t, err, "byte array: varlen=1, missing 1 bytes")
    // }

    #[test]
    fn test_decoder_byte_array_invalid_length() {
        let mut buf = vec![];
        buf.extend_from_slice(u32::to_le_bytes(999).as_ref());
        buf.extend_from_slice(&[0x01, 0x02]);

        let mut d = Decoder::new(buf);

        let data = d.read_byte_slice();
        assert!(data.is_err());
    }

    // 	func TestDecoder_ByteArray_InvalidLength2(t *testing.T) {
    // 	buf := []byte{
    // 		0x01, 0x00, 0x00, 0x00,
    // 		0x01,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	_, err := d.ReadByteSlice()
    // 	assert.EqualError(t, err, "byte array: varlen=1, missing 1 bytes")
    // }

    #[test]
    fn test_decoder_byte_array_invalid_length2() {
        let mut buf = vec![];
        buf.extend_from_slice(u32::to_le_bytes(100).as_ref());
        buf.extend_from_slice(&[0x01]);

        let mut d = Decoder::new(buf);

        let data = d.read_byte_slice();
        assert!(data.is_err());
    }

    // 	func TestDecoder_Int64(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x91, 0x7d, 0xf3, 0xff, 0xff, 0xff, 0xff, 0xff, //-819823
    // 		0xe3, 0x1c, 0x1, 0x00, 0x00, 0x00, 0x00, 0x00, //72931
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadInt64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(-819823), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadInt64(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(72931), n)
    // 	assert.Equal(t, 0, d.Remaining())

    // 	// big endian
    // 	buf = []byte{
    // 		0xff, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x7d, 0x91, //-819823
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x1, 0x1c, 0xe3, //72931
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadInt64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(-819823), n)
    // 	assert.Equal(t, 8, d.Remaining())

    // 	n, err = d.ReadInt64(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, int64(72931), n)
    // 	assert.Equal(t, 0, d.Remaining())
    // }

    #[test]
    fn test_decoder_int64_2() {
        // little endian
        let mut buf = vec![];
        buf.extend_from_slice(&[0x91, 0x7d, 0xf3, 0xff, 0xff, 0xff, 0xff, 0xff]); //-819823
        buf.extend_from_slice(&[0xe3, 0x1c, 0x1, 0x00, 0x00, 0x00, 0x00, 0x00]); //72931

        let mut d = Decoder::new(buf);

        let n = d.read_i64(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(-819823, n);
        assert_eq!(8, d.remaining());

        let n = d.read_i64(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(72931, n);
        assert_eq!(0, d.remaining());

        // big endian
        let mut buf = vec![];
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x7d, 0x91]); //-819823
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x1, 0x1c, 0xe3]); //72931

        let mut d = Decoder::new(buf);

        let n = d.read_i64(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(-819823, n);
        assert_eq!(8, d.remaining());

        let n = d.read_i64(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(72931, n);
        assert_eq!(0, d.remaining());
    }

    // 	func TestDecoder_Uint128_2(t *testing.T) {
    // 	// little endian
    // 	buf := []byte{
    // 		0x0d, 0x88, 0xd3, 0xff, 0xff, 0xff, 0xff, 0xff,
    // 		0x6d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 	}

    // 	d := NewBinDecoder(buf)

    // 	n, err := d.ReadUint128(LE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, Uint128{Hi: 0xb6d, Lo: 0xffffffffffd3880d}, n)

    // 	buf = []byte{
    // 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xbb,
    // 		0xff, 0xff, 0xff, 0xff, 0xff, 0xac, 0xdc, 0xad,
    // 	}

    // 	d = NewBinDecoder(buf)

    // 	n, err = d.ReadUint128(BE)
    // 	assert.NoError(t, err)
    // 	assert.Equal(t, Uint128{Hi: 0x00000000000008bb, Lo: 0xffffffffffacdcad}, n)
    // }

    #[test]
    fn test_decoder_uint128_2() {
        // little endian
        let mut buf = vec![];
        buf.extend_from_slice(&[0x0d, 0x88, 0xd3, 0xff, 0xff, 0xff, 0xff, 0xff]);
        buf.extend_from_slice(&[0x6d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let mut d = Decoder::new(buf);

        let n = d.read_u128(byte_order::ByteOrder::LittleEndian).unwrap();
        assert_eq!(0xb6d << 64 | 0xffffffffffd3880d, n);

        let mut buf = vec![];
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xbb]);
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xac, 0xdc, 0xad]);

        let mut d = Decoder::new(buf);

        let n = d.read_u128(byte_order::ByteOrder::BigEndian).unwrap();
        assert_eq!(0x00000000000008bb << 64 | 0xffffffffffacdcad, n);
    }

    // 	func TestDecoder_SkipBytes(t *testing.T) {
    // 	buf := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    // 	decoder := NewBinDecoder(buf)
    // 	err := decoder.SkipBytes(1)
    // 	require.NoError(t, err)
    // 	require.Equal(t, 7, decoder.Remaining())

    // 	err = decoder.SkipBytes(2)
    // 	require.NoError(t, err)
    // 	require.Equal(t, 5, decoder.Remaining())

    // 	err = decoder.SkipBytes(6)
    // 	require.Error(t, err)

    // 	err = decoder.SkipBytes(5)
    // 	require.NoError(t, err)
    // 	require.Equal(t, 0, decoder.Remaining())
    // }

    #[test]
    fn test_decoder_skip_bytes() {
        let mut buf = vec![];
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut decoder = Decoder::new(buf);
        decoder.skip(1).unwrap();
        assert_eq!(7, decoder.remaining());

        decoder.skip(2).unwrap();
        assert_eq!(5, decoder.remaining());

        decoder.skip(6).unwrap_err();

        decoder.skip(5).unwrap();
        assert_eq!(0, decoder.remaining());
    }

    // 	func Test_Discard(t *testing.T) {
    // 	buf := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
    // 	decoder := NewBinDecoder(buf)
    // 	err := decoder.Discard(5)
    // 	require.NoError(t, err)
    // 	require.Equal(t, 5, decoder.Remaining())
    // 	remaining, err := decoder.Peek(decoder.Remaining())
    // 	require.NoError(t, err)
    // 	require.Equal(t, []byte{5, 6, 7, 8, 9}, remaining)
    // }

    #[test]
    fn test_discard() {
        let mut buf = vec![];
        buf.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut decoder = Decoder::new(buf);
        decoder.discard(5).unwrap();
        assert_eq!(5, decoder.remaining());
        let remaining = decoder.peek(decoder.remaining()).unwrap();
        assert_eq!(vec![5, 6, 7, 8, 9], remaining);
    }

    // 	func TestDecoder_ReadBytes(t *testing.T) {
    // 	buf := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    // 	decoder := NewBinDecoder(buf)
    // 	b, err := decoder.ReadBytes(1)
    // 	require.NoError(t, err)
    // 	require.Equal(t, []byte{0xff}, b)
    // 	require.Equal(t, 7, decoder.Remaining())

    // 	b, err = decoder.ReadBytes(2)
    // 	require.NoError(t, err)
    // 	require.Equal(t, []byte{0xff, 0xff}, b)
    // 	require.Equal(t, 5, decoder.Remaining())

    // 	b, err = decoder.ReadBytes(6)
    // 	require.Error(t, err)

    // 	b, err = decoder.ReadBytes(5)
    // 	require.NoError(t, err)
    // 	require.Equal(t, []byte{0xff, 0xff, 0xff, 0xff, 0xff}, b)
    // 	require.Equal(t, 0, decoder.Remaining())
    // }

    #[test]
    fn test_decoder_read_bytes() {
        let mut buf = vec![];
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut decoder = Decoder::new(buf);
        let b = decoder.read_bytes(1).unwrap();
        assert_eq!(vec![0xff], b);
        assert_eq!(7, decoder.remaining());

        let b = decoder.read_bytes(2).unwrap();
        assert_eq!(vec![0xff, 0xff], b);
        assert_eq!(5, decoder.remaining());

        decoder.read_bytes(6).unwrap_err();

        let b = decoder.read_bytes(5).unwrap();
        assert_eq!(vec![0xff, 0xff, 0xff, 0xff, 0xff], b);
        assert_eq!(0, decoder.remaining());
    }

    // 	func Test_ReadNBytes(t *testing.T) {
    // 	{
    // 		b1 := []byte{123, 99, 88, 77, 66, 55, 44, 33, 22, 11}
    // 		b2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    // 		buf := concatByteSlices(
    // 			b1,
    // 			b2,
    // 		)
    // 		decoder := NewBinDecoder(buf)

    // 		got, err := decoder.ReadNBytes(10)
    // 		require.NoError(t, err)
    // 		require.Equal(t, b1, got)

    // 		got, err = decoder.ReadNBytes(10)
    // 		require.NoError(t, err)
    // 		require.Equal(t, b2, got)
    // 	}
    // }

    #[test]
    fn test_read_n_bytes() {
        let mut b1 = vec![];
        b1.extend_from_slice(&[123, 99, 88, 77, 66, 55, 44, 33, 22, 11]);
        let mut b2 = vec![];
        b2.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut buf = vec![];
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        let mut decoder = Decoder::new(buf);

        let got = decoder.read_n_bytes(10).unwrap();
        assert_eq!(b1, got);

        let got = decoder.read_n_bytes(10).unwrap();
        assert_eq!(b2, got);
    }

    // 	func Test_ReadNBytes_Error(t *testing.T) {
    // 	{
    // 		b1 := []byte{123, 99, 88, 77, 66, 55, 44, 33, 22, 11}
    // 		b2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    // 		buf := concatByteSlices(
    // 			b1,
    // 			b2,
    // 		)
    // 		decoder := NewBinDecoder(buf)

    // 		_, err := decoder.ReadNBytes(11)
    // 		require.Error(t, err)
    // 	}
    // }

    #[test]
    fn test_read_n_bytes_error() {
        let mut b1 = vec![];
        b1.extend_from_slice(&[123, 99, 88, 77, 66, 55, 44, 33, 22, 11]);
        let mut b2 = vec![];
        b2.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut buf = vec![];
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        let mut decoder = Decoder::new(buf);

        let res = decoder.read_n_bytes(9999);
        assert!(res.is_err());
    }

    // 	func Test_ReadBytes(t *testing.T) {
    // 	{
    // 		b1 := []byte{123, 99, 88, 77, 66, 55, 44, 33, 22, 11}
    // 		b2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    // 		buf := concatByteSlices(
    // 			b1,
    // 			b2,
    // 		)
    // 		decoder := NewBinDecoder(buf)

    // 		got, err := decoder.ReadBytes(10)
    // 		require.NoError(t, err)
    // 		require.Equal(t, b1, got)

    // 		got, err = decoder.ReadBytes(10)
    // 		require.NoError(t, err)
    // 		require.Equal(t, b2, got)
    // 	}
    // }

    #[test]
    fn test_read_bytes() {
        let mut b1 = vec![];
        b1.extend_from_slice(&[123, 99, 88, 77, 66, 55, 44, 33, 22, 11]);
        let mut b2 = vec![];
        b2.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut buf = vec![];
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        let mut decoder = Decoder::new(buf);

        let got = decoder.read_bytes(10).unwrap();
        assert_eq!(b1, got);

        let got = decoder.read_bytes(10).unwrap();
        assert_eq!(b2, got);
    }

    // 	func Test_Read(t *testing.T) {
    // 	{
    // 		b1 := []byte{123, 99, 88, 77, 66, 55, 44, 33, 22, 11}
    // 		b2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    // 		buf := concatByteSlices(
    // 			b1,
    // 			b2,
    // 		)
    // 		decoder := NewBinDecoder(buf)

    // 		{
    // 			got := make([]byte, 10)
    // 			num, err := decoder.Read(got)
    // 			require.NoError(t, err)
    // 			require.Equal(t, b1, got)
    // 			require.Equal(t, 10, num)
    // 		}

    // 		{
    // 			got := make([]byte, 10)
    // 			num, err := decoder.Read(got)
    // 			require.NoError(t, err)
    // 			require.Equal(t, b2, got)
    // 			require.Equal(t, 10, num)
    // 		}
    // 		{
    // 			got := make([]byte, 11)
    // 			_, err := decoder.Read(got)
    // 			require.EqualError(t, err, "short buffer")
    // 		}
    // 		{
    // 			got := make([]byte, 0)
    // 			num, err := decoder.Read(got)
    // 			require.NoError(t, err)
    // 			require.Equal(t, 0, num)
    // 			require.Equal(t, []byte{}, got)
    // 		}
    // 	}
    // }

    #[test]
    fn test_read() {
        let mut b1 = vec![];
        b1.extend_from_slice(&[123, 99, 88, 77, 66, 55, 44, 33, 22, 11]);
        let mut b2 = vec![];
        b2.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut buf = vec![];
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        let mut decoder = Decoder::new(buf);

        {
            let mut got = vec![];
            got.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let num = decoder.read(&mut got).unwrap();
            assert_eq!(b1, got);
            assert_eq!(10, num);
        }

        {
            let mut got = vec![];
            got.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let num = decoder.read(&mut got).unwrap();
            assert_eq!(b2, got);
            assert_eq!(10, num);
        }
        {
            let mut got = vec![];
            got.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let res = decoder.read(&mut got);
            assert!(res.is_err());
        }
        {
            let mut got = vec![];
            let num = decoder.read(&mut got).unwrap();
            assert_eq!(0, num);
            assert_eq!(vec![] as Vec<u8>, got);
        }
    }
}
